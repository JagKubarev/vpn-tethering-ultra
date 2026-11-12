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
