#!/system/bin/sh
# Оставляем бинарь под архитектуру устройства ($ARCH ставит Magisk/KSU/Apatch)
case "$ARCH" in
    arm64)
        rm -f "$MODPATH/bin/conntrack-arm"
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        ui_print "- static conntrack v1.4.8 (arm64)"
        ;;
    arm)
        rm -f "$MODPATH/bin/conntrack-arm64"
        set_perm "$MODPATH/bin/conntrack-arm" 0 0 0755
        ui_print "- static conntrack v1.4.8 (armv7)"
        ;;
    *)
        # неизвестная арх — оставляем оба, service.sh выберет по uname -m
        set_perm "$MODPATH/bin/conntrack-arm64" 0 0 0755
        set_perm "$MODPATH/bin/conntrack-arm"   0 0 0755
        ui_print "- static conntrack v1.4.8 (arm64+armv7)"
        ;;
esac
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh"  0 0 0755
