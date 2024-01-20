# AegisGuard

AegisGuard is a set of scripts to enhance the security of your Linux system by configuring Fail2Ban with UFW for securing SSH.

## Installation

To install AegisGuard, run the following command:

```bash
bash -c "$(wget -O- https://raw.githubusercontent.com/PyraScript/AegisGuard/main/AegisGuard.sh)"
```

## Security Management

Once installed, you can use the `manage_security` script to manage Fail2Ban and UFW. This script provides a user-friendly menu for various security-related actions.

To run the security management script, use:

```bash
manage_security
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

If you have suggestions or find issues, feel free to open an [issue](https://github.com/PyraScript/AegisGuard/issues) or create a [pull request](https://github.com/PyraScript/AegisGuard/pulls).

## Acknowledgments

- [Fail2Ban](https://www.fail2ban.org/)
- [UFW (Uncomplicated Firewall)](https://wiki.ubuntu.com/UncomplicatedFirewall)

Happy securing your system with AegisGuard!
