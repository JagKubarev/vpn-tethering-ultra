-- стенд 16.11 (в модуль не входит): «5 ACK» из доклада DEF CON 33 — перед ClientHello N пустых ACK с теми же
-- seq/ack, что у него (для сервера — обычные повторные подтверждения). Хотят «выбить» ClientHello за окно,
-- в котором ТСПУ собирает первые пакеты клиента. Как rst() из zapret-antidpi.lua, только флаг ACK.
-- arg: repeats=N (сколько), стандартный fooling (ip_ttl=N — не дальше N хопов)
function vt_preack(ctx, desync)
	direction_cutoff_opposite(ctx, desync)
	if not desync.dis.tcp or not desync.outgoing or not payload_check(desync) then return end
	if not replay_first(desync) then return end
	local dis = deepcopy(desync.dis)
	dis.payload = ""
	dis.tcp.th_flags = TH_ACK
	apply_fooling(desync, dis)
	apply_ip_id(desync, dis, nil, "none")
	DLOG("vt_preack: " .. (desync.arg.repeats or 1) .. " пустых ACK")
	rawsend_dissect_ipfrag(dis, desync_opts(desync))
end
