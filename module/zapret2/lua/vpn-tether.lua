-- VPN Tether: свои обманки для nfqws2 (подключается после zapret-lib.lua через --lua-init)
--
-- Подделки hardcorp74 (fake, hostfakesplit) держатся на метке времени TCP (tcp_ts): сервер
-- отбрасывает пакет со старой меткой. Windows метки не ставит (netsh ... timestamps по умолчанию
-- allowed), и у её соединений tcp_ts ничего не делает — поддельные части доходят до сервера как
-- настоящие (раздача на ноутбук 12.11: «нет интернета», SEC_E_ILLEGAL_MESSAGE).
-- Для таких пакетов — badseq + badack (сервер их тоже отбросит, а ТСПУ последовательность не сверяет).
-- Пакет с меткой не трогаем: у телефона и Linux/Android-клиентов всё как в hardcorp74.
-- Стенд 12.11 (YOTA, 12 сайтов × 2, 3 круга): с badseq+badack всегда — без меток 64 из 72 (было 38),
-- но с метками 66 из 72 (было 71); поэтому только когда метки нет.

-- fool=fool_nots: нет метки — tcp_seq=-10000, tcp_ack=-66000
function fool_nots(dis, fooling_options)
	if dis.tcp and not find_tcp_option(dis.tcp.options, TCP_KIND_TS) then
		dis.tcp.th_seq = u32add(dis.tcp.th_seq, -10000)
		dis.tcp.th_ack = u32add(dis.tcp.th_ack, -66000)
	end
end

-- fool=fool_nots_ack: нет метки — только tcp_ack=-66000 (поддельный ClientHello с badsum)
function fool_nots_ack(dis, fooling_options)
	if dis.tcp and not find_tcp_option(dis.tcp.options, TCP_KIND_TS) then
		dis.tcp.th_ack = u32add(dis.tcp.th_ack, -66000)
	end
end

-- vt_wssize_ramp (YT_WSSIZE_RAMP): малое окно приёма только до первых байт ответа сервера. ТСПУ режет
-- TLS с части адресов Google по началу ответа (16 03 03), но читает его лишь в пределах окна клиента
-- (вики zapret, «TLS по адресу», 10.2026); с окном 2 байта ответ проходит. Готовый wssize
-- (zapret-antidpi.lua) на YOTA давал TLS 1,9 с и почти нулевую скорость: он снимает подмену на
-- ClientHello, а масштаб в SYN уже занижен — ядро шлёт окно под свой масштаб, и сервер видит его в
-- 2^(свой - scale) раз меньше. Здесь:
--   SYN — масштаб scale (окно в самом SYN не масштабируется, не трогаем);
--   до ClientHello (ACK рукопожатия) — настоящее окно под масштаб scale: по нему Linux-сервер при
--     создании соединения запоминает наибольшее окно клиента и режет сегмент до его половины на всё
--     соединение (с окном 2 байта ответ шёл по 36 байт);
--   с ClientHello, пока клиент не подтвердил ни байта ответа (th_ack как в ACK рукопожатия), — wsize;
--   дальше — настоящее окно под масштаб scale, не больше 65535 (128 КБ при scale=1).
-- Нужны все исходящие пакеты соединения (--out-range=a --payload=all; правило VPN_YT_RAMP без
-- connbytes); входящие не нужны. Стенд 15.11 (YOTA, 17 молчащих стоек × 2): 34 из 34 против 19–28 без
-- него, TLS 0,84 с против 0,37 (ожидание persist-таймера сервера), скорость до ~5 Мбит/с при RTT 150 мс
-- arg: wsize=N (1), scale=N (1)
function vt_wssize_ramp(ctx, desync)
	local tcp = desync.dis.tcp
	if not tcp or not desync.outgoing then return end
	local st = desync.track and desync.track.lua_state
	if not st then return end
	local r = st.vt_ramp
	if not r then r = {}; st.vt_ramp = r end
	local scale = tonumber(desync.arg.scale) or 1
	if bitand(tcp.th_flags, TH_SYN) ~= 0 then
		local i = find_tcp_option(tcp.options, TCP_KIND_SCALE)
		if not i then return end
		local o = u8(tcp.options[i].data)
		if scale >= o then return end
		r.orig = o; r.ack0 = nil; r.small = nil; r.open = nil
		tcp.options[i].data = bu8(scale)
		return VERDICT_MODIFY
	end
	if not r.orig then return end
	if not r.ack0 then r.ack0 = tcp.th_ack end
	if not r.open then
		if tcp.th_ack ~= r.ack0 then
			r.open = true
		elseif r.small or #desync.dis.payload > 0 then
			r.small = true
			tcp.th_win = tonumber(desync.arg.wsize) or 1
			return VERDICT_MODIFY
		end
	end
	local w = math.floor(tcp.th_win * 2 ^ (r.orig - scale))
	if w > 65535 then w = 65535 end
	tcp.th_win = w
	return VERDICT_MODIFY
end
