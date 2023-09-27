# Compile the source files
all: Client.class CA.class

# Compile individual Java files
Client.class: Client.java
	javac Client.java

CA.class: CA.java
	javac CA.java
	

# Clean compiled files
clean:
	rm -f *.class