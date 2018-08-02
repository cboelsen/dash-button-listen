import argparse
import json
import logging
import os
import pwd

from pyHS100 import SmartPlug, Discover

from dhcp_sniffer import PyDhcpSniffer


log_format = '%(asctime)-15s: %(levelname)+8s - %(message)s'
logging.basicConfig(level=logging.INFO, format=log_format)


def notify_started():
    try:
        from systemd.daemon import notify, Notification
        notify(Notification.READY)
    except ImportError:
        pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('device')
    parser.add_argument('user')
    return parser.parse_args()


def drop_privileges(user):
    if os.getuid() != 0:
        return

    pwnam = pwd.getpwnam(user)

    os.setgroups(os.getgrouplist(pwnam.pw_name, pwnam.pw_gid))
    os.setgid(pwnam.pw_gid)
    os.setuid(pwnam.pw_uid)
    os.environ['HOME'] = pwnam.pw_dir

    logging.info('Dropped privileges to user "%s"', user)


def load_config():
    home = os.environ['HOME']
    config_file = os.path.join(home, '.dash_button_listen.json')
    logging.info('Loading config from "%s"', config_file)
    with open(config_file) as f:
        return json.load(f)


class PlugAddressCache:

    def __init__(self):
        self._cache = {}

    def discover_plugs(self):
        self._cache = {}
        devices = Discover.discover()
        for dev in devices.values():
            logging.info('Found plug "%s" at %s', dev.alias, dev.ip_address)
            self._cache[dev.alias.lower()] = SmartPlug(dev.ip_address)

    def get_plug(self, name):
        def _get():
            return self._cache[name.lower()]
        try:
            return _get()
        except Exception:
            self.discover_plugs()
            return _get()


cache = PlugAddressCache()


def toggle_plug(plug_name):
    plug = cache.get_plug(plug_name)
    if plug.is_on:
        logging.info('Turning plug "%s" off', plug.alias)
        plug.turn_off()
    else:
        logging.info('Turning plug "%s" on', plug.alias)
        plug.turn_on()


def standardise_mac(addr):
    return addr.lower().replace(':0', ':')


BUTTON_FUNCTIONS = {
    'toggle_plug': toggle_plug,
}


def main():
    args = parse_args()

    logging.info('Sniffing on "%s"', args.device)
    sniffer = PyDhcpSniffer(args.device)
    drop_privileges(args.user)

    config = load_config()
    notify_started()
    cache.discover_plugs()

    buttons = {standardise_mac(k): v for k, v in config['buttons'].items()}
    for addr in sniffer.mac_addresses():
        addr = standardise_mac(addr)
        if addr in buttons:
            button = buttons[addr]
            fn = BUTTON_FUNCTIONS[button['fn']]
            args = button['args']
            fn(*args)


if __name__ == "__main__":
    main()
