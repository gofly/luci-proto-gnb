'use strict';
'require uci';
'require form';
'require network';
'require fs';
'require rpc';
'require ui';
'require validation';


var generateKeyPair = rpc.declare({
  object: 'luci.gnb',
  method: 'generateKeyPair',
  expect: { keys: {} }
});

var stubValidator = {
  factory: validation,
  apply: function (type, value, args) {
    if (value != null)
      this.value = value;
    args = args || [];
    if (!validation.types || !validation.types[type])
      return false;
    return validation.types[type].apply(this, args);
  },
  assert: function (condition) {
    return !!condition;
  },
  validateHex: function (length, value) {
    if (!value || typeof value !== 'string') return false;
    if (value.length !== length) return false;
    return stubValidator.apply('hexstring', value);
  },
  Disabled: function (section_id, value) {
    if (value == null) return _('Crypto setting is missing or invalid');
    if (['xor', 'arc4', 'none'].indexOf(String(value)) !== -1) return true;
    return _('Crypto setting is missing or invalid');
  },
  NodeID: function (section_id, value) {
    if (stubValidator.apply('range', value, [0, 9999])) return true;
    return _('Node ID setting is missing or invalid');
  },
  PrivateKey: function (section_id, value) {
    if (stubValidator.validateHex(128, value)) return true;
    return _('Private Key setting is missing or invalid');
  },
  PublicKey: function (optional) {
    return function (section_id, value) {
      if ((optional && !value) || stubValidator.validateHex(64, value)) return true;
      return _('Public Key setting is missing or invalid');
    }
  },
  IPAddr: function (section_id, value) {
    var arr = Array.isArray(value) ? value : String(value).split(/[, ]+/).filter(Boolean);
    for (var i = 0; i < arr.length; i++) {
      if (!stubValidator.apply('cidr4', arr[i])) return _('IPAddr setting is invalid');
    }
    return true;
  },
  Passcode: function (section_id, value) {
    if (stubValidator.validateHex(8, value)) return true;
    return _('Passcode setting is missing or invalid');
  },
  Crypto: function (section_id, value) {
    if (['xor', 'arc4', 'none'].indexOf(String(value)) !== -1) return true;
    return _('Crypto setting is missing or invalid');
  },
  MultiSocket: function (section_id, value) {
    if (value == null) return true;
    var v = String(value);
    if (v === '0' || v === '1' || v === 'true' || v === 'false') return true;
    return _('MultiSocket setting is missing or invalid');
  },
  Listen: function (section_id, value) {
    if (!value) return true;
    var arr = Array.isArray(value) ? value : String(value).split(/[, ]+/).filter(Boolean);
    for (var i = 0; i < arr.length; i++) {
      if (!stubValidator.apply('port', arr[i])) return _('Listen setting is missing or invalid');
    }
    return true;
  },
  NodeType: function (section_id, value) {
    if (!value) return _('Node Type setting is missing or invalid');
    var arr = Array.isArray(value) ? value : String(value).split(/[, ]+/).filter(Boolean);
    if (arr.length === 0) return _('Node Type setting is missing or invalid');
    for (var i = 0; i < arr.length; i++) {
      if (['n', 'i', 'u', 'r', 's', 'f'].indexOf(arr[i]) === -1)
        return _('Node Type setting is missing or invalid');
    }
    return true;
  },
  Subnet: function (section_id, value) {
    if (!value) return true;
    var arr = Array.isArray(value) ? value : String(value).split(/[, ]+/).filter(Boolean);
    for (var i = 0; i < arr.length; i++) {
      if (!stubValidator.apply('cidr4', arr[i])) return _('Subnet setting is missing or invalid');
    }
    return true;
  },
  RouteSubnet: function (section_id, value) {
    if (value == null) return true;
    var v = String(value);
    if (v === '0' || v === '1') return true;
    return _('RouteSubnet setting is missing or invalid');
  },
  Address: function (section_id, value) {
    if (!value) return true;
    var arr = Array.isArray(value) ? value : String(value).split(/[, ]+/).filter(Boolean);
    for (var i = 0; i < arr.length; i++) {
      if (!stubValidator.apply('hostport', arr[i])) return _('Address setting is missing or invalid');
    }
    return true;
  }
};

function downloadText(filename, text) {
  var pom = document.createElement('a');
  pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  pom.setAttribute('download', filename);
  if (document.createEvent) {
    var event = document.createEvent('MouseEvents');
    event.initEvent('click', true, true);
    pom.dispatchEvent(event);
  } else {
    pom.click();
  }
}

function handleWindowDragDropIgnore(ev) {
  ev.preventDefault();
}

var cbiKeyPairGenerate = form.DummyValue.extend({
  cfgvalue: function (section_id, value) {
    return E('button', {
      'class': 'btn create-keypair',
      'click': ui.createHandlerFn(this, function (section_id, ev) {
        var priv = this.section.getUIElement(section_id, 'private_key'),
          pub = this.section.getUIElement(section_id, 'public_key'),
          map = this.map;
        if (!priv || !pub) {
          ui.addNotification(null, E('p', [_('UI element missing: cannot set keys')]), 'error');
          return;
        }
        if (priv.getValue() && pub.getValue()) {
          if (!confirm(_('Private Key and Public Key is not empty, overwrite?')))
            return;
        }
        return generateKeyPair().then(function (res) {
          if (!res) {
            ui.addNotification(null, E('p', [_('Key generation failed: invalid response')]), 'error');
            return;
          }
          if (res.priv) priv.setValue(res.priv);
          if (res.pub) pub.setValue(res.pub);
          map.save(null, true);
        }).catch(function (err) {
          ui.addNotification(null, E('p', [_('Key generation failed: %s').format(String(err || ''))]), 'error');
        });
      }, section_id)
    }, [_('Generate new key pair')]);
  }
});

network.registerPatternVirtual(/^gnb-.+$/);

return network.registerProtocol('gnb', {
  getI18n: function () {
    return _('GNB VPN');
  },

  getIfname: function () {
    return this._ubus('l3_device') || 'gnb-%s'.format(this.sid);
  },

  getPackageName: function () {
    return 'gnb-vpn';
  },

  isFloating: function () {
    return true;
  },

  isVirtual: function () {
    return true;
  },

  getDevices: function () {
    return null;
  },

  containsDevice: function (ifname) {
    return (network.getIfnameOf(ifname) == this.getIfname());
  },

  renderFormOptions: function (s) {
    var dev = this.getL3Device() || this.getDevice(), o, ss;

    o = s.taboption('general', form.Button, '_import', _('Import configuration'), _('Imports settings from an existing GNB configuration file'));
    o.inputtitle = _('Load configuration…');
    o.onclick = function () {
      return ss.handleConfigImport('full');
    };

    o = s.taboption('general', form.DummyValue, '_export', _('Export configuration'), _('Exports settings to a GNB configuration file'));
    o.exportConfig = function (section_id, ev) {
      var nodeid = s.formvalue(s.section, 'node_id') || '',
        priv = s.formvalue(s.section, 'private_key') || '',
        pub = s.formvalue(s.section, 'public_key') || '',
        ipaddr = s.formvalue(s.section, 'ipaddr') || '',
        passcode = s.formvalue(s.section, 'passcode') || '',
        crypto = s.formvalue(s.section, 'crypto') || '',
        multisocket = s.formvalue(s.section, 'multisocket');
      multisocket = multisocket == null ? '0' : String(multisocket);

      var confContent = [];
      confContent.push('[Interface]',
        'NodeID=' + nodeid,
        'PrivateKey=' + priv,
        'PublicKey=' + pub,
        'IPAddr=' + ipaddr,
        'PassCode=' + passcode,
        'Crypto=' + crypto,
        'MultiSocket=' + multisocket);

      var listen = s.formvalue(s.section, 'listen');
      if (listen.length > 0)
        confContent.push('Listen=' + (Array.isArray(listen) ? listen.join(',') : listen));
      confContent.push('');

      uci.sections('network', 'gnb_' + s.section, function (peer) {
        confContent.push('[Peer]');
        confContent.push('NodeID=' + (peer.node_id || ''));
        confContent.push('PublicKey=' + (peer.public_key || ''));
        confContent.push('IPAddr=' + (peer.ipaddr || ''));
        confContent.push('NodeType=' + (peer.node_type || ''));
        if (peer.subnet != null) confContent.push('Subnet=' + peer.subnet);
        if (peer.address != null) confContent.push('Address=' + peer.address);
        if (peer.route_subnet != null) confContent.push('RouteSubnet=' + peer.route_subnet);
        if (peer.disabled != null) confContent.push('Disabled=' + peer.disabled);
        confContent.push('');
      });

      downloadText('gnb-node-%s.conf'.format(nodeid), confContent.join('\n'));
    };
    o.cfgvalue = function (section_id, value) {
      var pubkey = this.section.cfgvalue(section_id, 'public_key');
      return E('button', {
        'class': 'btn',
        'style': 'display:inline-flex;align-items:center;gap:.5em',
        'click': ui.createHandlerFn(this, 'exportConfig', section_id),
        'disabled': pubkey ? null : ''
      }, [
        _('Generate configuration…')
      ]);
    };

    o = s.taboption('general', form.Value, 'node_id', _('Node ID'), _('Required. Numbers from 0 to 9999'));
    o.placeholder = '1000';
    o.validate = stubValidator.NodeID;

    o = s.taboption('general', form.TextValue, 'private_key', _('Private Key'), _('Required. Hex-encoded private key for this interface.'));
    o.validate = stubValidator.PrivateKey;
    o.wrap = true;

    o = s.taboption('general', form.TextValue, 'public_key', _('Public Key'), _('Required. Hex-encoded public key of this interface for sharing.'));
    o.validate = stubValidator.PublicKey(false);
    o.wrap = true;

    s.taboption('general', cbiKeyPairGenerate, '_gen_server_keypair', ' ');

    o = s.taboption('general', form.DynamicList, 'ipaddr', _('IPv4 address'), _('Such as 192.168.100.1/24'));
    o.validate = stubValidator.IPAddr;

    o = s.taboption('general', form.Value, 'passcode', _('Passcode'), _('Hex-encoded 8 characters preshared key'));
    o.validate = stubValidator.Passcode;
    o.password = true;

    o = s.taboption('general', form.DummyValue, '_gen_passcode', ' ');
    o.modalonly = true;
    o.cfgvalue = function (section_id, value) {
      return E('button', {
        'class': 'btn',
        'click': ui.createHandlerFn(this, function (section_id, ev) {
          var psk = this.section.getUIElement(section_id, 'passcode');
          if (!psk) {
            ui.addNotification(null, E('p', [_('UI element missing: passcode')]), 'error');
            return;
          }
          if (psk.getValue()) {
            if (!confirm(_('Passcode is not empty, overwrite?')))
              return;
          }
          var hex = Math.floor(Math.random() * 0xFFFFFFFF)
            .toString(16)
            .padStart(8, '0');
          psk.setValue(hex);
          this.map.save(null, true);
        }, section_id),
      }, [_('Generate preshared key')]);
    };

    o = s.taboption('general', form.ListValue, 'crypto', _('Crypto'));
    o.value('xor');
    o.value('arc4');
    o.value('none');
    o.validate = stubValidator.Crypto;

    o = s.taboption('general', form.Flag, 'multisocket', _('Multi Socket'));
    o.modalonly = true;
    o.validate = stubValidator.MultiSocket;
    o.default = o.disabled;

    o = s.taboption('general', form.DynamicList, 'listen', _('Listen'));
    o.validate = stubValidator.Listen;
    o.placeholder = '9001';

    o = s.taboption('advanced', form.Value, 'mtu', _('Override MTU'));
    o.datatype = 'range(68, 9200)';
    o.placeholder = dev ? (dev.getMTU()) : '';

    try {
      s.tab('peers', _('Peers'), _('GNB peers'));
    }
    catch (e) { }

    o = s.taboption('peers', form.SectionValue, '_peers', form.GridSection, 'gnb_%s'.format(s.section));
    o.depends('proto', 'gnb');

    ss = o.subsection;
    ss.anonymous = true;
    ss.addremove = true;
    ss.addbtntitle = _('Add peer');
    ss.nodescriptions = true;
    ss.modaltitle = _('Edit peer');

    ss.handleDragConfig = function (ev) {
      ev.stopPropagation();
      ev.preventDefault();
      ev.dataTransfer.dropEffect = 'copy';
    };

    ss.handleDropConfig = function (mode, ev) {
      var file = ev.dataTransfer.files && ev.dataTransfer.files[0],
        nodes = ev.currentTarget,
        input = nodes.querySelector('textarea'),
        reader = new FileReader();

      if (file) {
        reader.onload = function (rev) {
          input.value = rev.target.result.trim();
          ss.handleApplyConfig(mode, nodes, file.name, ev);
        };

        reader.readAsText(file);
      }

      ev.stopPropagation();
      ev.preventDefault();
    };

    ss.parseConfig = function (mode, data) {
      var lines = String(data).split(/\r?\n/),
        section = null,
        peers = [],
        config = { peers: {} },
        sobj = null, i;

      for (i = 0; i < lines.length; i++) {
        var raw = lines[i].replace(/#.*$/, '').trim();
        if (!raw) continue;

        var m = raw.match(/^\[(\w+)\]$/);
        if (m) {
          section = m[1].toLowerCase();
          if (section === 'peer') {
            sobj = {};
            peers.push(sobj);
          } else {
            sobj = config;
          }
          continue;
        }

        var kv = raw.match(/^(\w+)\s*=\s*(.*)$/);
        if (kv && section) {
          var key = kv[1].toLowerCase();
          var val = kv[2].trim();
          if (val.length) {
            var prefix = (section === 'peer') ? 'peer_' : 'interface_';
            sobj[prefix + key] = val;
          }
        }
      }

      if (mode === 'full') {
        if (stubValidator.NodeID('', config.interface_nodeid) !== true) return _('Node ID setting is missing or invalid');
        if (stubValidator.PrivateKey('', config.interface_privatekey) !== true) return _('PrivateKey setting is missing or invalid');
        if (stubValidator.PublicKey(false)('', config.interface_publickey) !== true) return _('PublicKey setting is missing or invalid');
        if (stubValidator.IPAddr('', config.interface_ipaddr) !== true) return _('IP Address setting is missing or invalid');
        if (stubValidator.Passcode('', config.interface_passcode) !== true) return _('Passcode setting is missing or invalid');
        if (stubValidator.Crypto('', config.interface_crypto) !== true) return _('Crypto setting is missing or invalid');

        if (!config.interface_multisocket) config.interface_multisocket = '0';

        if (config.interface_listen) {
          config.interface_listen = config.interface_listen.split(/[, ]+/).filter(Boolean);
          if (stubValidator.Listen('', config.interface_listen) !== true) return _('Listen setting is invalid');
        } else {
          config.interface_listen = [];
        }
      }

      for (i = 0; i < peers.length; i++) {
        var pconf = peers[i];
        if (stubValidator.NodeID('', pconf.peer_nodeid) !== true) return _('Node ID is invalid');
        if (stubValidator.PublicKey(true)('', pconf.peer_publickey) !== true) return _('PublicKey setting is invalid');

        if (!pconf.peer_nodetype) pconf.peer_nodetype = ['n'];
        else {
          pconf.peer_nodetype = String(pconf.peer_nodetype).split(/[, ]+/).filter(Boolean);
          if (stubValidator.NodeType('', pconf.peer_nodetype) !== true) return _('NodeType setting is missing or invalid');
        }

        if (stubValidator.IPAddr('', pconf.peer_ipaddr) !== true) return _('IPAddr setting is invalid');

        if (!pconf.peer_subnet) pconf.peer_subnet = [];
        else {
          pconf.peer_subnet = String(pconf.peer_subnet).split(/[, ]+/).filter(Boolean);
          if (stubValidator.Subnet('', pconf.peer_subnet) !== true) return _('Subnet setting is invalid');
        }

        if (!pconf.peer_routesubnet) pconf.peer_routesubnet = '1';
        else if (stubValidator.RouteSubnet('', pconf.peer_routesubnet) !== true) return _('RouteSubnet setting is missing or invalid');

        if (!pconf.peer_address) pconf.peer_address = [];
        else {
          pconf.peer_address = String(pconf.peer_address).split(/[, ]+/).filter(Boolean);
          if (stubValidator.Address('', pconf.peer_address) !== true) return _('Address setting is invalid');
        }

        if (typeof pconf.peer_disabled !== 'undefined') pconf.peer_disabled = String(pconf.peer_disabled);

        config.peers[pconf.peer_nodeid] = pconf;
      }

      return config;
    };

    ss.handleApplyConfig = function (mode, nodes, comment, ev) {
      var input = nodes.querySelector('textarea').value,
        error = nodes.querySelector('.alert-message'),
        cancel = nodes.nextElementSibling.querySelector('.btn'),
        config = this.parseConfig(mode, input),
        updateObjs, i;

      if (typeof (config) === 'string') {
        error.firstChild.data = _('Cannot parse configuration: %s').format(config);
        error.style.display = 'block';
        return;
      }

      if (mode == 'full') {
        var priv_current = s.formvalue(s.section, 'private_key');
        if (priv_current && priv_current != config.interface_privatekey) {
          if (!confirm(_('Overwrite the current settings with the imported configuration?')))
            return;
        }

        updateObjs = {
          node_id: config.interface_nodeid,
          private_key: config.interface_privatekey,
          public_key: config.interface_publickey,
          ipaddr: config.interface_ipaddr,
          passcode: config.interface_passcode,
          crypto: config.interface_crypto,
          multisocket: config.interface_multisocket,
          listen: config.interface_listen,
        };
        Object.keys(updateObjs).forEach(function (key) {
          if (typeof updateObjs[key] !== 'undefined')
            s.getOption(key).getUIElement(s.section).setValue(updateObjs[key]);
        });
      }

      uci.sections('network', 'gnb_' + s.section, function (peer) {
        if (config.peers[peer.node_id] !== null)
          uci.remove('network', peer['.name']);
      });

      for (i in config.peers) {
        var pconf = config.peers[i],
          sid = uci.add('network', 'gnb_' + s.section);
        updateObjs = {
          disabled: pconf.peer_disabled,
          node_id: pconf.peer_nodeid,
          node_type: pconf.peer_nodetype,
          public_key: pconf.peer_publickey,
          ipaddr: pconf.peer_ipaddr,
          subnet: pconf.peer_subnet,
          route_subnet: pconf.peer_routesubnet,
          address: pconf.peer_address,
        };
        Object.keys(updateObjs).forEach(function (key) {
          if (typeof updateObjs[key] !== 'undefined')
            uci.set('network', sid, key, updateObjs[key]);
        });
      }

      cancel.click();
      return s.map.save(null, true);
    };

    ss.handleConfigImport = function (mode) {
      var mapNode = ss.getActiveModalMap(),
        headNode = mapNode.parentNode.querySelector('h4');
      var nodes = E('div', {
        'dragover': this.handleDragConfig,
        'drop': this.handleDropConfig.bind(this, mode)
      }, [
        E([], (mode == 'full') ? [
          E('p', _('Drag or paste a valid <em>*.conf</em> file below to configure the local GNB interface.'))
        ] : [
          E('p', _('Paste or drag GNB configuration (commonly <em>gnb1001.conf</em>) from another system below to create a matching peer entry allowing that system to connect to the local GNB interface.')),
          E('p', _('To configure fully the local GNB interface from an existing (e.g. provider supplied) configuration file, use the <strong><a class="full-import" href="#">configuration import</a></strong> instead.'))
        ]),
        E('p', [
          E('textarea', {
            'placeholder': (mode == 'full') ? _('Paste or drag supplied GNB configuration file…') : _('Paste or drag GNB peer configuration (gnb1001.conf) file…'),
            'style': 'height:5em;width:100%; white-space:pre'
          })
        ]),
        E('div', {
          'class': 'alert-message',
          'style': 'display:none'
        }, [''])
      ]);

      var cancelFn = function () {
        nodes.parentNode.removeChild(nodes.nextSibling);
        nodes.parentNode.removeChild(nodes);
        mapNode.classList.remove('hidden');
        mapNode.nextElementSibling.querySelectorAll('.btn').forEach(function (node) {
          node.classList.remove('hidden');
        });
        if (headNode.lastChild && headNode.lastChild.nodeType === 1)
          headNode.removeChild(headNode.lastChild);
        window.removeEventListener('dragover', handleWindowDragDropIgnore);
        window.removeEventListener('drop', handleWindowDragDropIgnore);
      };

      mapNode.classList.add('hidden');
      mapNode.nextElementSibling.querySelectorAll('.btn').forEach(function (node) {
        node.classList.add('hidden');
      });
      headNode.appendChild(E('span', [' » ', _('Import config')]));
      mapNode.parentNode.appendChild(E([], [
        nodes,
        E('div', {
          'class': 'right'
        }, [
          E('button', {
            'class': 'btn',
            'click': cancelFn
          }, [_('Cancel')]),
          ' ',
          E('button', {
            'class': 'btn primary',
            'click': ui.createHandlerFn(this, 'handleApplyConfig', mode, nodes, null)
          }, [_('Import settings')])
        ])
      ]));

      window.addEventListener('dragover', handleWindowDragDropIgnore);
      window.addEventListener('drop', handleWindowDragDropIgnore);
    };

    ss.renderSectionAdd = function () {
      var nodes = this.super('renderSectionAdd', arguments);

      nodes.appendChild(E('button', {
        'class': 'btn',
        'click': ui.createHandlerFn(this, 'handleConfigImport', 'peer')
      }, [_('Import configuration as peer…')]));

      return nodes;
    };

    ss.renderSectionPlaceholder = function () {
      return E('em', _('No peers defined yet.'));
    };

    o = ss.option(form.Flag, 'disabled', _('Disabled'), _('Enable / Disable peer. Restart GNB interface to apply changes.'));
    o.editable = true;
    o.default = o.disabled;

    o = ss.option(form.Value, 'node_id', _('Node ID'), _('Required. Numbers from 0 to 9999'));
    o.placeholder = '1000';
    o.validate = stubValidator.NodeID;
    o.textvalue = function (section_id) {
      var dis = ss.getOption('disabled'),
        pub = ss.getOption('public_key'),
        nodetype = ss.getOption('node_type'),
        name = this.cfgvalue(section_id),
        key = pub.cfgvalue(section_id),
        nodetypes = L.toArray(nodetype.cfgvalue(section_id)),
        desc = [E('p', [name ? E('span', [name]) : E('em', [_('Untitled peer')])])],
        ntdesc = [];

      if (dis && dis.cfgvalue(section_id) == '1')
        desc.push(E('span', { 'class': 'ifacebadge', 'data-tooltip': _('GNB peer is disabled') }, [E('em', [_('Disabled')])]), ' ');

      if (!key || !pub.isValid(section_id)) {
        desc.push(E('span', { 'class': 'ifacebadge', 'data-tooltip': _('Public key is missing') }, [E('em', [_('Key missing')])]));
      } else {
        desc.push(E('span', { 'class': 'ifacebadge', 'data-tooltip': _('Public key: %h').format(key) }, [E('code', [key.replace(/^(.{5}).+(.{6})$/, '$1…$2')])]), ' ');
      }

      var kt = nodetype && nodetype.keylist ? nodetype.keylist : [];
      var vt = nodetype && nodetype.vallist ? nodetype.vallist : [];
      for (var m = 0; m < nodetypes.length; m++) {
        for (var n = 0; n < kt.length; n++) {
          if (kt[n] == nodetypes[m]) {
            ntdesc.push(vt[n] || kt[n]);
          }
        }
      }
      desc.push(E('span', { 'class': 'ifacebadge', 'data-tooltip': _('Node type: %h').format(ntdesc.join(', ')) }, [_(nodetypes.join(''))]));

      return E([], desc);
    };

    o = ss.option(form.MultiValue, 'node_type', _('Node Type'), _('Node Type.'));
    o.value('n', _('Normal'));
    o.value('i', _('Index'));
    o.value('f', _('Forward'));
    o.value('u', _('Unified'));
    o.value('r', _('Relay'));
    o.value('s', _('Silence'));
    o.multiple = true;
    o.validate = stubValidator.NodeType;
    o.modalonly = true;

    o = ss.option(form.DynamicList, 'ipaddr', _('IPv4 address'), _('Optional. IPv4 address.'));
    o.validate = stubValidator.IPAddr;
    o.placeholder = '192.168.100.1/24';

    o = ss.option(form.TextValue, 'public_key', _('Public Key'), _('Public key of the GNB peer.'));
    o.validate = stubValidator.PublicKey(true);
    o.modalonly = true;

    o = ss.option(form.DynamicList, 'subnet', _('Subnet'), _("Subnet that this peer is allowed to use inside the tunnel, like 192.168.100.2/255.255.255.0"));
    o.validate = stubValidator.Subnet;
    o.textvalue = function (section_id) {
      var subnets = L.toArray(this.cfgvalue(section_id)),
        list = [];

      for (var i = 0; i < subnets.length; i++) {
        if (i > 2) {
          list.push(E('em', { 'class': 'ifacebadge cbi-tooltip-container' }, [
            _('+ %d more').format(subnets.length - i),
            E('span', { 'class': 'cbi-tooltip' }, [
              E('ul', subnets.slice(i).map(function (subnet) {
                return E('li', [E('span', { 'class': 'ifacebadge' }, [subnet])]);
              }))
            ])
          ]));
          break;
        }
        list.push(E('span', { 'class': 'ifacebadge' }, [subnets[i]]));
      }

      return E('span', { 'style': 'display:inline-flex;flex-wrap:wrap;gap:.125em' }, list);
    };

    o = ss.option(form.Flag, 'route_subnet', _('Route Subnet'), _('Create routes for Subnet for this peer.'));
    o.validate = stubValidator.RouteSubnet;
    o.default = o.enabled;
    o.editable = true;

    o = ss.option(form.DynamicList, 'address', _('Address'), _('Optional. Address of peer.'));
    o.validate = stubValidator.Address;
    o.textvalue = function (section_id) {
      var addrs = L.toArray(this.cfgvalue(section_id)),
        list = [];
      for (var i = 0; i < addrs.length; i++) {
        list.push(E('div', {}, [addrs[i]]));
      }
      return E('div', {}, list);
    };
  },

  deleteConfiguration: function () {
    uci.sections('network', 'gnb_%s'.format(this.sid), function (s) {
      uci.remove('network', s['.name']);
    });
  }
});