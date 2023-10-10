# Compile the source files
all: set_class_path Client.class CA.class GUI.class

# Compile individual Java files
Client.class: Client.java
	javac Client.java

CA.class: CA.java
	javac CA.java

GUI.class: GUI.java
	javac GUI.java

set_class_path:
	export CLASSPATH=./:./bouncycastle.jar
	

# Clean compiled files
clean:
	rm -f *.class