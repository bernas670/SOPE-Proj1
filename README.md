# Digital Forensic Analysis Tool
Forensic analysis utility for directories and files in Unix / Linux environment.

## Project Info
* **Date** : 2nd Year, 2nd Semester, 2018/2019
* **Course** : [Sistemas Operativos](https://sigarra.up.pt/feup/pt/ucurr_geral.ficha_uc_view?pv_ocorrencia_id=419998) | [Operating Systems](https://sigarra.up.pt/feup/en/UCURR_GERAL.FICHA_UC_VIEW?pv_ocorrencia_id=419998) (SOPE)
* **Contributors** : [Bernardo Santos](https://github.com/bernas670), [Vítor Gonçalves](https://github.com/torrinheira), [António Dantas](https://github.com/antoniopedrodantas)
* **Specification** : [Portuguese](specification.pdf)
* **License** : [MIT](LICENSE)

### Use
**`forensic [-r] [-h [md5[,sha1[,sha256]]] [-o <outfile>] [-v] <file|dir>`**
* `-r` : analyse all files in the specified directory and all subdirectories
* `-h` : calculate one or more cryptographic hash of the analysed files (*if more than one argument is wanted separate them with commas*)
* `-o` : store the analysis data in a CSV file (*not in the standard output*)
* `-v` : generate a log file


## Development Plan
- [x] Receive, handle and save arguments and environment variables.
- [x] Extract the solicited information from just one file and print it to the standard output according to the parsed arguments.
	- [x] Same procedure but now, implementing the option **`-o`** (writing in the specified file).
- [x] Repeat the previous step for all files in a directory.
- [ ] When a directory is found, create a child process capable of repeating its father's functions, performing a similar job to the previous step.
- [ ] Implement recursive analysis of a directory tree.
- [ ] Add logging funtionalities.
- [ ] Handle the signal associated to CTRL+C.
- [ ] Implement issuing and handling of the signals SIGUSR1 and SIGUSR2.
