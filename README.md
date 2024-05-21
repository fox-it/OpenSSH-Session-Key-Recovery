# OpenSSH Session Key Recovery
Project containing several tools/ scripts to recover the OpenSSH session keys used to encrypt/ decrypt SSH traffic. More information can be found in [this blogpost](https://blog.fox-it.com/2020/11/11/decrypting-openssh-sessions-for-fun-and-profit/).

# Volatility 3 Usage

## Without changing the volatility3 repository

### Use the plugin

Put the plugin path after the `-p` flag.

### Give the symbol

The correct symbol file (openssh32 or openssh64) must be in the directory given after the `-s`.

Or put both, the plugin can choose the right one.

## Adding the files in the repository

### Plugin

Plugin file can be added to `volatility3/framework/plugins/linux`

### Symbols

Symbols can be added to `volatility3/framework/symbols/linux`