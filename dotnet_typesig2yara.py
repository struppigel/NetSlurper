import os
import argparse
import hashlib
import sys
import subprocess

# This tool creates a Yara rule containing a method's type signature. 
# It needs the fully qualified name for a method in a .NET file
# as well as the file itself.
#
# Prerequisite: Put ildasm.exe in PATH variable
# Usage: dotnet_typesig2yara.py "foo.bar::Baz" sample.exe

def readSigBytes(infile, method):
	signature = 'no signature found'
	sig_description = ''
	process = subprocess.Popen(['ildasm', '/text', '/bytes', '/nobar', '/item="' + method + '"', infile], 
                           stdout=subprocess.PIPE)
	sig_desc_start = False
	
	for line in process.stdout:
		line = line.decode('UTF-8')
		if '.method ' in line:
			sig_desc_start = True	
		if 'SIG:' in line:
			splitted = line.split('SIG:')
			signature = splitted[1].strip()
			break
		if sig_desc_start:
			sig_description += '\t\t' + line.strip() + '\n'
	return signature, sig_description.strip()
	
def getHashFromFile(infile):
	readable_hash = ""
	with open(infile,"rb") as f:
		bytes = f.read() # read entire file as bytes
		readable_hash = hashlib.sha256(bytes).hexdigest();
	return readable_hash
	
def printYaraStub(signature, comment, infile):
	author = os.environ['username'].replace('.', ' ')
	readable_hash = getHashFromFile(infile)
	
	yara_sig_text = """rule Signature : MSIL
{{
	meta:
		author = "{}"
		description = ".NET based malware"
		sha256 = "{}"
	strings:
		/*
		{}
		*/
		$method_signature = {{ {} }}
	condition:
		all of them
}}""".format(author,readable_hash, comment, signature)

	print(yara_sig_text)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='NetSlurper, .NET Type Signature Extractor')
	parser.add_argument('method', help='Method to create signature from either as token (must start with "0x") or fully qualified name, e.g., "Foo.Bar::Baz", "0x0600002a"')
	parser.add_argument('infile', help='Input file to create signature from, must be .NET assembly')
	args = parser.parse_args()
	method = args.method
	infile = args.infile
	
	print("Note: This doesn't support all types yet, e.g., Generic Types. The output for those might be wrong")
	
	signature, sig_description = readSigBytes(infile, method)
	printYaraStub(signature, sig_description, infile)