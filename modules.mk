mod_dynaconf.la: mod_dynaconf.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dynaconf.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_dynaconf.la
