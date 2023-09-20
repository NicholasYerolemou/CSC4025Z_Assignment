# Compile the source files
all: Client.class Session.class CA.class Server.class Test.class

# Compile individual Java files
Client.class: Client.java
	javac Client.java

Session.class: Session.java
	javac Session.java

CA.class: CA.java
	javac CA.java

Server.class: Server.java
	javac Server.java

Test.class: Test.java
	javac Test.java

# Run the tests
test: all
	@java Test
	

# Clean compiled files
clean:
	rm -f Client.class Session.class CA.class Server.class Test.class