# Compile the source files
all: Client.class CA.class GUI.class

# Compile individual Java files
Client.class: Client.java
	javac -cp ".:./bouncycastle.jar" Client.java

CA.class: CA.java
	javac -cp ".:./bouncycastle.jar" CA.java

GUI.class: GUI.java
	javac GUI.java
	

# Clean compiled files
clean:
	rm -f *.class