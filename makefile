# Compile the source files
all: ImageData.class Client.class CA.class GUI.class

# Compile individual Java files
Client.class: Client.java
	export CLASSPATH=./:./bouncycastle.jar
	javac Client.java

CA.class: CA.java
	export CLASSPATH=./:./bouncycastle.jar
	javac CA.java

GUI.class: GUI.java
	export CLASSPATH=./:./bouncycastle.jar
	javac GUI.java

ImageData.class: ImageData.java
	export CLASSPATH=./:./bouncycastle.jar
	javac ImageData.java
	

# Clean compiled files
clean:
	rm -f *.class