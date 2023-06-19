package org.keycloak.events.logging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.jpa.EventEntity;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;

import javax.persistence.EntityManager;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LastLoginEventListenerProvider
        implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(LastLoginEventListenerProvider.class);
    private static final String LAST_LOGIN = "lastLogin";
    private static final String PREVIOUS_LOGIN = "previousLogin";

    private final KeycloakSession session;
    private final RealmProvider model;
    ObjectMapper mapper = new ObjectMapper();

    public LastLoginEventListenerProvider(KeycloakSession session) {
        this.session = session;
        this.model = session.realms();
    }

    @Override
    public void onEvent(Event event) {
        if (EventType.LOGIN.equals(event.getType())) {
            RealmModel realm = this.model.getRealm(event.getRealmId());
            UserModel user = this.session.users().getUserById(realm, event.getUserId());

            if (user != null) {
                log.info("Updating last login status for user: " + event.getUserId());

                Map<String, List<String>> userAttrs = user.getAttributes();
                if (userAttrs.containsKey(LAST_LOGIN)) {
                    List<String> userLastLogin = userAttrs.get(LAST_LOGIN);
                    if (userLastLogin != null && !userLastLogin.isEmpty()) {
                        String prevLogin = userLastLogin.get(0);
                        user.setSingleAttribute(PREVIOUS_LOGIN, prevLogin);
                        event.getDetails().put(PREVIOUS_LOGIN, prevLogin);
                    }
                }

                // Use current server time for login event
                OffsetDateTime loginTime = OffsetDateTime.now(ZoneOffset.UTC);
                String loginTimeS = DateTimeFormatter.ISO_DATE_TIME.format(loginTime);
                user.setSingleAttribute(LAST_LOGIN, loginTimeS);
                event.getDetails().put(LAST_LOGIN, loginTimeS);

                if(realm.isEventsEnabled())
                    updateEventEntity(event);
            }
        }
    }

    private void updateEventEntity(Event event){
        JpaConnectionProvider connection = session.getProvider(JpaConnectionProvider.class);
        EntityManager entityManager = connection.getEntityManager();
        EventEntity eventEntity = entityManager.find(EventEntity.class, event.getId());
        if(eventEntity != null){
            String detailsJson = eventEntity.getDetailsJson();
            try {
                var details = mapper.readValue(detailsJson, new TypeReference<HashMap<String, String>>() {});
                details.put(LAST_LOGIN, event.getDetails().get(LAST_LOGIN));
                if(event.getDetails().containsKey(PREVIOUS_LOGIN))
                    details.put(PREVIOUS_LOGIN, event.getDetails().get(PREVIOUS_LOGIN));
                eventEntity.setDetailsJson(mapper.writeValueAsString(details));
            } catch (IOException var4) {
                log.error("Failed to write log details", var4);
            }

            entityManager.merge(eventEntity);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
    }

    @Override
    public void close() {
        // Nothing to close
    }
}