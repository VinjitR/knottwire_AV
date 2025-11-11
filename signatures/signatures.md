
1. Download the latest ClamAV database files (such as `main.cvd`, `daily.cvd`, or their `.cld`/`.cvd` variants) from the [ClamAV database download page](https://www.clamav.net/downloads).
2. Extract the `.mdb` signature files from the downloaded database using the `sigtool` utility:
   ```
   sigtool --unpack-current main.cvd
   sigtool --unpack-current daily.cvd
   ```
   or for `.cld` files:
   ```
   sigtool --unpack-current main.cld
   ```
3. Locate the extracted `.mdb` files in the output directory.
4. Convert the `.mdb` files to a JSON lines format for easier processing. You can use the following example Python script:
   ```python
   import json

   with open('main.mdb', 'r') as infile, open('clamav_signatures.jsonl', 'w') as outfile:
       for line in infile:
           fields = line.strip().split(':')
           # Adjust the structure below according to your .mdb signature format
           record = {
               "type": "mdb",
               "name": fields[0],
               "md5": fields[1],
               "size": fields[2],
               "raw": line.strip()
           }
           outfile.write(json.dumps(record) + "\n")
   ```
5. Repeat this process for each `.mdb` file you have extracted.
6. Combine all the `.jsonl` files if multiple `.mdb` files are present.
7. Resulting JSON lines file (e.g., `clamav_signatures.jsonl`) can now be imported or used by KnottWire.

