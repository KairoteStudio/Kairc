package server

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KairoteStudio/Kairc/internal/irc"
)

type inbound struct {
	client  *client
	message irc.Message
}

type departure struct {
	client *client
	reason string
}

type channel struct {
	name       string
	members    map[*client]struct{}
	operators  map[*client]struct{}
	topic      string
	topicSetBy string
	topicSetAt int64
}

type hub struct {
	cfg        Config
	log        *slog.Logger
	createdAt  time.Time
	register   chan *client
	unregister chan departure
	incoming   chan inbound
	done       chan struct{}
	clients    map[*client]struct{}
	nicks      map[string]*client
	channels   map[string]*channel
}

func newHub(cfg Config, logger *slog.Logger) *hub {
	return &hub{
		cfg:        cfg,
		log:        logger,
		createdAt:  time.Now().UTC(),
		register:   make(chan *client),
		unregister: make(chan departure),
		incoming:   make(chan inbound),
		done:       make(chan struct{}),
		clients:    make(map[*client]struct{}),
		nicks:      make(map[string]*client),
		channels:   make(map[string]*channel),
	}
}

func (h *hub) run(ctx context.Context) {
	defer close(h.done)
	for {
		select {
		case <-ctx.Done():
			for c := range h.clients {
				c.close()
			}
			return
		case c := <-h.register:
			h.clients[c] = struct{}{}
			h.log.Info("IRC client connected", "remote", c.host, "client_id", c.id)
		case event := <-h.unregister:
			h.drop(event.client, event.reason)
		case event := <-h.incoming:
			if _, ok := h.clients[event.client]; ok {
				h.handle(event.client, event.message)
			}
		}
	}
}

func (h *hub) handle(c *client, msg irc.Message) {
	switch msg.Command {
	case "CAP":
		h.handleCAP(c, msg.Params)
	case "NICK":
		h.handleNICK(c, msg.Params)
	case "USER":
		h.handleUSER(c, msg.Params)
	case "PING":
		if len(msg.Params) == 0 {
			h.numeric(c, 409, "No origin specified")
		} else {
			h.send(c, irc.Format(h.cfg.Name, "PONG", h.cfg.Name, msg.Params[len(msg.Params)-1]))
		}
	case "PONG":
		// A PONG is intentionally a no-op; receiving it is enough.
	case "PASS":
		if c.ready.Load() {
			h.numeric(c, 462, "You may not reregister")
		}
	case "QUIT":
		reason := "Client Quit"
		if len(msg.Params) > 0 && msg.Params[0] != "" {
			reason = msg.Params[0]
		}
		h.drop(c, reason)
		c.close()
	default:
		if !c.ready.Load() {
			h.numeric(c, 451, "You have not registered")
			return
		}
		h.handleRegistered(c, msg)
	}
}

func (h *hub) handleRegistered(c *client, msg irc.Message) {
	switch msg.Command {
	case "JOIN":
		h.handleJOIN(c, msg.Params)
	case "PART":
		h.handlePART(c, msg.Params)
	case "PRIVMSG", "NOTICE":
		h.handleMessage(c, msg.Command, msg.Params)
	case "TOPIC":
		h.handleTOPIC(c, msg.Params)
	case "KICK":
		h.handleKICK(c, msg.Params)
	case "NAMES":
		h.handleNAMES(c, msg.Params)
	case "LIST":
		h.handleLIST(c)
	case "WHO":
		h.handleWHO(c, msg.Params)
	case "WHOIS":
		h.handleWHOIS(c, msg.Params)
	case "MODE":
		h.handleMODE(c, msg.Params)
	case "MOTD":
		h.sendMOTD(c)
	case "LUSERS":
		h.sendLusers(c)
	case "VERSION":
		h.numeric(c, 351, Version, h.cfg.Name, "Kairc — KairoteStudio IRC server")
	case "TIME":
		h.numeric(c, 391, h.cfg.Name, time.Now().UTC().Format(time.RFC1123))
	case "AWAY":
		if len(msg.Params) == 0 || msg.Params[0] == "" {
			h.numeric(c, 305, "You are no longer marked as being away")
		} else {
			h.numeric(c, 306, "You have been marked as being away")
		}
	case "ISON":
		h.handleISON(c, msg.Params)
	default:
		h.numeric(c, 421, msg.Command, "Unknown command")
	}
}

func (h *hub) handleCAP(c *client, params []string) {
	if len(params) == 0 {
		return
	}
	subcommand := strings.ToUpper(params[0])
	switch subcommand {
	case "LS":
		c.capNegotiating = true
		h.send(c, irc.Format(h.cfg.Name, "CAP", h.nickOrStar(c), "LS", ""))
	case "LIST":
		h.send(c, irc.Format(h.cfg.Name, "CAP", h.nickOrStar(c), "LIST", ""))
	case "REQ":
		request := ""
		if len(params) > 1 {
			request = params[len(params)-1]
		}
		h.send(c, irc.Format(h.cfg.Name, "CAP", h.nickOrStar(c), "NAK", request))
	case "END":
		c.capNegotiating = false
		h.maybeRegister(c)
	}
}

func (h *hub) handleNICK(c *client, params []string) {
	if len(params) == 0 || params[0] == "" {
		h.numeric(c, 431, "No nickname given")
		return
	}
	nick := params[0]
	if !validNick(nick) {
		h.numeric(c, 432, nick, "Erroneous nickname")
		return
	}
	key := foldIRC(nick)
	if owner, exists := h.nicks[key]; exists && owner != c {
		h.numeric(c, 433, nick, "Nickname is already in use")
		return
	}

	oldNick := c.nick
	oldPrefix := c.prefix()
	if oldNick != "" {
		delete(h.nicks, foldIRC(oldNick))
	}
	c.nick = nick
	h.nicks[key] = c

	if c.ready.Load() {
		line := irc.Format(oldPrefix, "NICK", nick)
		for peer := range h.sharedPeers(c, true) {
			h.send(peer, line)
		}
		return
	}
	h.maybeRegister(c)
}

func (h *hub) handleUSER(c *client, params []string) {
	if c.ready.Load() || c.username != "" {
		h.numeric(c, 462, "You may not reregister")
		return
	}
	if len(params) < 4 {
		h.numeric(c, 461, "USER", "Not enough parameters")
		return
	}
	c.username = safeIdent(params[0])
	c.realname = params[3]
	h.maybeRegister(c)
}

func (h *hub) maybeRegister(c *client) {
	if c.ready.Load() || c.nick == "" || c.username == "" || c.capNegotiating {
		return
	}
	c.ready.Store(true)
	_ = c.conn.SetReadDeadline(time.Time{})
	h.numeric(c, 1, "Welcome to the "+h.cfg.Network+" Network "+c.prefix())
	h.numeric(c, 2, "Your host is "+h.cfg.Name+", running Kairc "+Version)
	h.numeric(c, 3, "This server was created "+h.createdAt.Format(time.RFC1123))
	h.numeric(c, 4, h.cfg.Name, "Kairc-"+Version, "o", "n")
	h.numeric(c, 5, "CHANTYPES=#&", "CASEMAPPING=rfc1459", "NICKLEN=24", "CHANNELLEN=50", "PREFIX=(o)@", "CHANMODES=,,,nt", "NETWORK="+h.cfg.Network, "are supported by this server")
	h.sendLusers(c)
	h.sendMOTD(c)
	h.log.Info("IRC client registered", "nick", c.nick, "remote", c.host, "client_id", c.id)
}

func (h *hub) handleJOIN(c *client, params []string) {
	if len(params) == 0 || params[0] == "" {
		h.numeric(c, 461, "JOIN", "Not enough parameters")
		return
	}
	if params[0] == "0" {
		keys := make([]string, 0, len(c.channels))
		for key := range c.channels {
			keys = append(keys, key)
		}
		for _, key := range keys {
			h.part(c, key, "Leaving")
		}
		return
	}
	for _, requested := range strings.Split(params[0], ",") {
		if !validChannel(requested) {
			h.numeric(c, 403, requested, "No such channel")
			continue
		}
		key := foldIRC(requested)
		if _, exists := c.channels[key]; exists {
			continue
		}
		room := h.channels[key]
		if room == nil {
			room = &channel{
				name:      requested,
				members:   make(map[*client]struct{}),
				operators: make(map[*client]struct{}),
			}
			h.channels[key] = room
		}
		firstMember := len(room.members) == 0
		room.members[c] = struct{}{}
		c.channels[key] = room
		if firstMember {
			room.operators[c] = struct{}{}
		}
		line := irc.Format(c.prefix(), "JOIN", room.name)
		for member := range room.members {
			h.send(member, line)
		}
		h.sendTopic(c, room)
		h.sendNames(c, room)
	}
}

func (h *hub) handlePART(c *client, params []string) {
	if len(params) == 0 || params[0] == "" {
		h.numeric(c, 461, "PART", "Not enough parameters")
		return
	}
	reason := "Leaving"
	if len(params) > 1 && params[1] != "" {
		reason = params[1]
	}
	for _, requested := range strings.Split(params[0], ",") {
		key := foldIRC(requested)
		room := h.channels[key]
		if room == nil {
			h.numeric(c, 403, requested, "No such channel")
			continue
		}
		if _, member := room.members[c]; !member {
			h.numeric(c, 442, room.name, "You're not on that channel")
			continue
		}
		h.part(c, key, reason)
	}
}

func (h *hub) part(c *client, key, reason string) {
	room := h.channels[key]
	if room == nil {
		return
	}
	line := irc.Format(c.prefix(), "PART", room.name, reason)
	for member := range room.members {
		h.send(member, line)
	}
	delete(room.members, c)
	delete(room.operators, c)
	delete(c.channels, key)
	if len(room.members) == 0 {
		delete(h.channels, key)
	} else {
		h.ensureOperator(room)
	}
}

func (h *hub) handleMessage(c *client, command string, params []string) {
	notice := command == "NOTICE"
	fail := func(code int, reply ...string) {
		if !notice {
			h.numeric(c, code, reply...)
		}
	}
	if len(params) == 0 || params[0] == "" {
		fail(411, "No recipient given ("+command+")")
		return
	}
	if len(params) < 2 || params[1] == "" {
		fail(412, "No text to send")
		return
	}
	text := params[1]
	for _, target := range strings.Split(params[0], ",") {
		if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
			key := foldIRC(target)
			room := h.channels[key]
			if room == nil {
				fail(403, target, "No such channel")
				continue
			}
			if _, member := room.members[c]; !member {
				fail(404, room.name, "Cannot send to channel")
				continue
			}
			line := irc.Format(c.prefix(), command, room.name, text)
			for member := range room.members {
				if member != c {
					h.send(member, line)
				}
			}
			continue
		}

		recipient := h.nicks[foldIRC(target)]
		if recipient == nil || !recipient.ready.Load() {
			fail(401, target, "No such nick/channel")
			continue
		}
		h.send(recipient, irc.Format(c.prefix(), command, recipient.nick, text))
	}
}

func (h *hub) handleTOPIC(c *client, params []string) {
	if len(params) == 0 {
		h.numeric(c, 461, "TOPIC", "Not enough parameters")
		return
	}
	room := h.channels[foldIRC(params[0])]
	if room == nil {
		h.numeric(c, 403, params[0], "No such channel")
		return
	}
	if len(params) == 1 {
		h.sendTopic(c, room)
		return
	}
	if _, member := room.members[c]; !member {
		h.numeric(c, 442, room.name, "You're not on that channel")
		return
	}
	if _, operator := room.operators[c]; !operator {
		h.numeric(c, 482, room.name, "You're not channel operator")
		return
	}
	room.topic = params[1]
	room.topicSetBy = c.nick
	room.topicSetAt = time.Now().Unix()
	line := irc.Format(c.prefix(), "TOPIC", room.name, room.topic)
	for member := range room.members {
		h.send(member, line)
	}
}

func (h *hub) handleKICK(c *client, params []string) {
	if len(params) < 2 {
		h.numeric(c, 461, "KICK", "Not enough parameters")
		return
	}
	room := h.channels[foldIRC(params[0])]
	if room == nil {
		h.numeric(c, 403, params[0], "No such channel")
		return
	}
	if _, member := room.members[c]; !member {
		h.numeric(c, 442, room.name, "You're not on that channel")
		return
	}
	if _, operator := room.operators[c]; !operator {
		h.numeric(c, 482, room.name, "You're not channel operator")
		return
	}
	target := h.nicks[foldIRC(params[1])]
	if target == nil {
		h.numeric(c, 401, params[1], "No such nick/channel")
		return
	}
	if _, member := room.members[target]; !member {
		h.numeric(c, 441, target.nick, room.name, "They aren't on that channel")
		return
	}
	reason := c.nick
	if len(params) > 2 && params[2] != "" {
		reason = params[2]
	}
	line := irc.Format(c.prefix(), "KICK", room.name, target.nick, reason)
	for member := range room.members {
		h.send(member, line)
	}
	key := foldIRC(room.name)
	delete(room.members, target)
	delete(room.operators, target)
	delete(target.channels, key)
	if len(room.members) == 0 {
		delete(h.channels, key)
	} else {
		h.ensureOperator(room)
	}
}

func (h *hub) sendTopic(c *client, room *channel) {
	if room.topic == "" {
		h.numeric(c, 331, room.name, "No topic is set")
		return
	}
	h.numeric(c, 332, room.name, room.topic)
	h.numeric(c, 333, room.name, room.topicSetBy, strconv.FormatInt(room.topicSetAt, 10))
}

func (h *hub) handleNAMES(c *client, params []string) {
	if len(params) == 0 || params[0] == "" {
		keys := make([]string, 0, len(h.channels))
		for key := range h.channels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			h.sendNames(c, h.channels[key])
		}
		return
	}
	for _, name := range strings.Split(params[0], ",") {
		room := h.channels[foldIRC(name)]
		if room == nil {
			h.numeric(c, 366, name, "End of /NAMES list")
			continue
		}
		h.sendNames(c, room)
	}
}

func (h *hub) sendNames(c *client, room *channel) {
	names := make([]string, 0, len(room.members))
	for member := range room.members {
		if member.ready.Load() {
			prefix := ""
			if _, operator := room.operators[member]; operator {
				prefix = "@"
			}
			names = append(names, prefix+member.nick)
		}
	}
	sort.Slice(names, func(i, j int) bool { return foldIRC(names[i]) < foldIRC(names[j]) })

	var batch []string
	flush := func() {
		if len(batch) > 0 {
			h.numeric(c, 353, "=", room.name, strings.Join(batch, " "))
			batch = batch[:0]
		}
	}
	for _, name := range names {
		trial := append(append([]string(nil), batch...), name)
		if irc.Numeric(h.cfg.Name, 353, h.nickOrStar(c), "=", room.name, strings.Join(trial, " ")) == "" {
			flush()
		}
		batch = append(batch, name)
	}
	flush()
	h.numeric(c, 366, room.name, "End of /NAMES list")
}

func (h *hub) handleLIST(c *client) {
	h.numeric(c, 321, "Channel", "Users  Name")
	keys := make([]string, 0, len(h.channels))
	for key := range h.channels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		room := h.channels[key]
		h.numeric(c, 322, room.name, strconv.Itoa(len(room.members)), room.topic)
	}
	h.numeric(c, 323, "End of /LIST")
}

func (h *hub) handleWHO(c *client, params []string) {
	if len(params) == 0 {
		h.numeric(c, 315, "*", "End of /WHO list")
		return
	}
	target := params[0]
	room := h.channels[foldIRC(target)]
	if room != nil {
		members := make([]*client, 0, len(room.members))
		for member := range room.members {
			members = append(members, member)
		}
		sort.Slice(members, func(i, j int) bool { return foldIRC(members[i].nick) < foldIRC(members[j].nick) })
		for _, member := range members {
			flags := "H"
			if _, operator := room.operators[member]; operator {
				flags += "@"
			}
			h.numeric(c, 352, room.name, member.username, member.host, h.cfg.Name, member.nick, flags, "0 "+member.realname)
		}
	}
	h.numeric(c, 315, target, "End of /WHO list")
}

func (h *hub) handleWHOIS(c *client, params []string) {
	if len(params) == 0 || params[len(params)-1] == "" {
		h.numeric(c, 431, "No nickname given")
		return
	}
	target := params[len(params)-1]
	member := h.nicks[foldIRC(target)]
	if member == nil || !member.ready.Load() {
		h.numeric(c, 401, target, "No such nick/channel")
		h.numeric(c, 318, target, "End of /WHOIS list")
		return
	}
	h.numeric(c, 311, member.nick, member.username, member.host, "*", member.realname)
	h.numeric(c, 312, member.nick, h.cfg.Name, h.cfg.Network)
	if len(member.channels) > 0 {
		names := make([]string, 0, len(member.channels))
		for _, room := range member.channels {
			names = append(names, room.name)
		}
		sort.Strings(names)
		h.numeric(c, 319, member.nick, strings.Join(names, " "))
	}
	h.numeric(c, 318, member.nick, "End of /WHOIS list")
}

func (h *hub) handleMODE(c *client, params []string) {
	if len(params) == 0 || params[0] == "" {
		h.numeric(c, 461, "MODE", "Not enough parameters")
		return
	}
	target := params[0]
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "&") {
		room := h.channels[foldIRC(target)]
		if room == nil {
			h.numeric(c, 403, target, "No such channel")
			return
		}
		if len(params) == 1 {
			h.numeric(c, 324, room.name, "+nt")
			return
		}
		if _, operator := room.operators[c]; !operator {
			h.numeric(c, 482, room.name, "You're not channel operator")
			return
		}
		mode := params[1]
		if mode != "+o" && mode != "-o" {
			h.numeric(c, 472, mode, "is unknown mode char to me")
			return
		}
		if len(params) < 3 {
			h.numeric(c, 461, "MODE", "Not enough parameters")
			return
		}
		target := h.nicks[foldIRC(params[2])]
		if target == nil {
			h.numeric(c, 401, params[2], "No such nick/channel")
			return
		}
		if _, member := room.members[target]; !member {
			h.numeric(c, 441, target.nick, room.name, "They aren't on that channel")
			return
		}
		if mode == "+o" {
			room.operators[target] = struct{}{}
		} else {
			delete(room.operators, target)
		}
		line := irc.Format(c.prefix(), "MODE", room.name, mode, target.nick)
		for member := range room.members {
			h.send(member, line)
		}
		h.ensureOperator(room)
		return
	}
	member := h.nicks[foldIRC(target)]
	if member != c {
		h.numeric(c, 502, "Cannot change mode for other users")
		return
	}
	if len(params) == 1 {
		h.numeric(c, 221, "+")
	}
}

func (h *hub) handleISON(c *client, params []string) {
	var online []string
	for _, group := range params {
		for _, nick := range strings.Fields(group) {
			if member := h.nicks[foldIRC(nick)]; member != nil && member.ready.Load() {
				online = append(online, member.nick)
			}
		}
	}
	h.numeric(c, 303, strings.Join(online, " "))
}

func (h *hub) sendLusers(c *client) {
	registered := 0
	for member := range h.clients {
		if member.ready.Load() {
			registered++
		}
	}
	h.numeric(c, 251, fmt.Sprintf("There are %d users and 0 services on 1 server", registered))
	h.numeric(c, 254, strconv.Itoa(len(h.channels)), "channels formed")
	h.numeric(c, 255, fmt.Sprintf("I have %d clients and 1 server", registered))
}

func (h *hub) sendMOTD(c *client) {
	h.numeric(c, 375, "- "+h.cfg.Name+" Message of the Day -")
	lines := strings.Split(h.cfg.MOTD, "\n")
	for _, line := range lines {
		if line != "" {
			h.numeric(c, 372, "- "+line)
		}
	}
	h.numeric(c, 376, "End of /MOTD command")
}

func (h *hub) drop(c *client, reason string) {
	if _, exists := h.clients[c]; !exists {
		return
	}
	delete(h.clients, c)
	if c.nick != "" {
		delete(h.nicks, foldIRC(c.nick))
	}
	if c.ready.Load() {
		line := irc.Format(c.prefix(), "QUIT", reason)
		for peer := range h.sharedPeers(c, false) {
			h.send(peer, line)
		}
	}
	for key, room := range c.channels {
		delete(room.members, c)
		delete(room.operators, c)
		if len(room.members) == 0 {
			delete(h.channels, key)
		} else {
			h.ensureOperator(room)
		}
	}
	c.channels = make(map[string]*channel)
	c.close()
	h.log.Info("IRC client disconnected", "nick", c.nick, "remote", c.host, "client_id", c.id, "reason", reason)
}

func (h *hub) ensureOperator(room *channel) {
	if len(room.members) == 0 || len(room.operators) > 0 {
		return
	}
	var next *client
	for member := range room.members {
		if next == nil || foldIRC(member.nick) < foldIRC(next.nick) {
			next = member
		}
	}
	room.operators[next] = struct{}{}
	line := irc.Format(h.cfg.Name, "MODE", room.name, "+o", next.nick)
	for member := range room.members {
		h.send(member, line)
	}
}

func (h *hub) sharedPeers(c *client, includeSelf bool) map[*client]struct{} {
	peers := make(map[*client]struct{})
	for _, room := range c.channels {
		for member := range room.members {
			if includeSelf || member != c {
				peers[member] = struct{}{}
			}
		}
	}
	if includeSelf {
		peers[c] = struct{}{}
	}
	return peers
}

func (h *hub) send(c *client, line string) {
	if line != "" {
		c.enqueue(line)
	}
}

func (h *hub) numeric(c *client, code int, params ...string) {
	all := make([]string, 0, len(params)+1)
	all = append(all, h.nickOrStar(c))
	all = append(all, params...)
	h.send(c, irc.Numeric(h.cfg.Name, code, all...))
}

func (h *hub) nickOrStar(c *client) string {
	if c.nick == "" {
		return "*"
	}
	return c.nick
}

func validNick(nick string) bool {
	if len(nick) == 0 || len(nick) > 24 {
		return false
	}
	for i := 0; i < len(nick); i++ {
		ch := nick[i]
		letter := ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
		special := strings.ContainsRune("[]\\`_^{|}", rune(ch))
		if i == 0 {
			if !letter && !special {
				return false
			}
			continue
		}
		if !letter && !special && !(ch >= '0' && ch <= '9') && ch != '-' {
			return false
		}
	}
	return true
}

func validChannel(name string) bool {
	if len(name) < 2 || len(name) > 50 || name[0] != '#' && name[0] != '&' {
		return false
	}
	for i := 1; i < len(name); i++ {
		ch := name[i]
		if ch <= ' ' || ch == ',' || ch == ':' || ch == 0x7f {
			return false
		}
	}
	return true
}

func safeIdent(value string) string {
	var b strings.Builder
	for i := 0; i < len(value) && b.Len() < 24; i++ {
		ch := value[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune("_-.", rune(ch)) {
			b.WriteByte(ch)
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

// foldIRC implements the RFC 1459 casemap: ASCII letters plus the equivalent
// bracket characters compare case-insensitively.
func foldIRC(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'A' && ch <= 'Z':
			b.WriteByte(ch + ('a' - 'A'))
		case ch == '[':
			b.WriteByte('{')
		case ch == ']':
			b.WriteByte('}')
		case ch == '\\':
			b.WriteByte('|')
		case ch == '^':
			b.WriteByte('~')
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
