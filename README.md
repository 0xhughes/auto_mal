# auto_mal
This Python script is used to perform triage analysis of sorts on SWF and OLE sample files. Using some yara signatures created by Didier Stevens (http://blog.didierstevens.com/), some keyword checking, SWFTools (http://www.swftools.org/), and an OLE analysis module provided by Decalage (http://www.decalage.info/python/oletools), an output CSV file is created containing information to help triage further analysis targets from batches of potential malware samples.

This script was written and tested in Kali v2 using Python 2.7.

You will need to ensure a number of things are installed for the script to function.

The following commands may help ensure your environment is ready to run the script.

pip install oletools
apt-get install swftools
apt-get install python-magic
pip install yara
