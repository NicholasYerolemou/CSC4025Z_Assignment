import javax.crypto.SecretKey;

//An instance of this class is created once a session has been established by a client
//It holds all the data this client has sent/recieved in this session
//Is deleted when session is ended
public class Session {

    private String targetIP;
    private SecretKey sessionKey;
    private String[] messages;

    public Session(String targetIP, SecretKey sessionKey) {
        this.targetIP = targetIP;
        this.sessionKey = sessionKey;
    }

    public String getTargetIP() {
        return targetIP;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public void addMessage(String m) {

        // add message to messages array
    }

}
