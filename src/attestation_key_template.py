import sys
f = open(sys.argv[1])
f2 = open(sys.argv[2], "w")

f2.write("#ifndef ATTESTATION_KEY_H\n")
f2.write("#define ATTESTATION_KEY_H\n")
f2.write("\n")

key = "static uint8_t attestation_key[] = \""
for line in f.read().split("\n"):
	key += line + "\\n"

key += "\";"

f2.write(key+"\n")
f2.write("\n")
f2.write("#endif\n")
	
