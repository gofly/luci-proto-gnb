#
# Copyright (C) 2025 Lixin Zheng <lixin.zhenglx@gmail.com>
#
# This is free software, licensed under the GNU General Public License, Version 3.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-proto-gnb
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Lixin Zheng<lixin.zheng@gmail.com>
PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

LUCI_TITLE:=
LUCI_DEPENDS:=+gnb +ucode
LUCI_PKGARCH:=all

define Package/luci-proto-gnb
	SECTION:=LuCI
	CATEGORY:=Protocols
	DEPENDS:=+gnb
	TITLE:=GNB VPN protocol support for LuCI
	MAINTAINER:=Lixin Zheng<lixin.zheng@gmail.com>
	PKGARCH:=all
endef

define Package/luci-proto-gnb/description
	GNB VPN protocol support for LuCI
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/root $(PKG_BUILD_DIR)/htdocs
	$(CP) ./root/* $(PKG_BUILD_DIR)/root/
	$(CP) ./htdocs/* $(PKG_BUILD_DIR)/htdocs/
	$(call Build/Prepare/Default)
endef

define Package/luci-proto-gnb/install
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/lib/netifd/proto/gnb.sh $(1)/lib/netifd/proto
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/rpcd/acl.d/luci-proto-gnb.json $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/rpcd/ucode/luci.gnb $(1)/usr/share/rpcd/ucode
	$(INSTALL_DIR) $(1)/www/luci-static/resources/protocol
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/protocol/gnb.js $(1)/www/luci-static/resources/protocol
endef

define Build/Compile
endef

$(eval $(call BuildPackage,luci-proto-gnb))