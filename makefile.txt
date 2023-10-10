# Compile the source files
all: Client.class CA.class GUI.class

# Compile individual Java files
Client.class: Client.java
	javac Client.java

CA.class: CA.java
	javac CA.java

GUI.class: GUI.java
	javac GUI.java
	

# Clean compiled files
clean:
	rm -f *.class