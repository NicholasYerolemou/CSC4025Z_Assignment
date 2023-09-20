# Compile the source files
all: Client.class Server.class

# Compile individual Java files
Client.class: Client.java
	javac Client.java

Server.class: Server.java
	javac Server.java

	

# Clean compiled files
clean:
	rm -f *.class