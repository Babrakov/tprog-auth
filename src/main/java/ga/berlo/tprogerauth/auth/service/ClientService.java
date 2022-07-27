package ga.berlo.tprogerauth.auth.service;

public interface ClientService {
    void register(String clientId, String clientSecret);
    void checkCredentials(String clientId, String clientSecret);
}
