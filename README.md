# logsh
Utility for running commands in a logged context without disclosing what was run.

## Usage
Edit `script.sh` and run make to generate: 
* `logsh` with embedded encrypted scripts and decryption keys
* `decrypt` with embedded decryption keys

To decrypt logsh output, run ./decrypt ./logsh-log.txt

To simply test your script end to end, run `make end-to-end`
