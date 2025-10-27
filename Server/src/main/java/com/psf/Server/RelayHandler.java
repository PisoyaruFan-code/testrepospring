package com.psf.Server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.psf.Server.Utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RelayHandler extends TextWebSocketHandler {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, SessionInfo> clients = new ConcurrentHashMap<>();
    private final JwtUtil jwtUtil;

    public RelayHandler(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    private static class SessionInfo {
        final WebSocketSession session;
        final String role; // "user" or "admin" or "guest"
        final Instant registeredAt;
        final String username; // optional (for admin)
        SessionInfo(WebSocketSession s, String r, String u) { session = s; role = r; username = u; registeredAt = Instant.now(); }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        clients.entrySet().removeIf(e -> e.getValue().session.equals(session));
    }

    @Override
    public void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        Map msg = mapper.readValue(message.getPayload(), Map.class);
        String type = (String) msg.get("type");
        if ("register".equals(type)) {
            handleRegister(session, msg);
            return;
        }

        if ("relay".equals(type)) {
            handleRelay(session, msg);
            return;
        }

        // admin-only operations (list, admin_send) — require role=admin on the caller's session
        if ("admin_list_sessions".equals(type)) {
            handleAdminList(session, msg);
            return;
        }
        if ("admin_send".equals(type)) {
            handleAdminSend(session, msg);
            return;
        }

        sendError(session, "unknown_type", "Unknown type: " + type);
    }

    private void handleRegister(WebSocketSession session, Map<String,Object> msg) throws Exception {
        String id = (String) msg.get("id");
        String roleRequested = (String) msg.getOrDefault("role", "guest"); // guest by default

        if (id == null || id.isBlank()) {
            sendError(session, "bad_request", "Missing id");
            return;
        }

        if ("admin".equals(roleRequested)) {
            String token = (String) msg.get("auth_token");
            if (token == null) {
                sendError(session, "auth_failed", "Missing auth_token for admin");
                session.close(CloseStatus.NOT_ACCEPTABLE.withReason("auth_failed"));
                return;
            }
            try {
                Jws<Claims> claims = jwtUtil.validate(token);
                String sub = claims.getBody().getSubject();
                String role = (String) claims.getBody().get("role");
                if (!"admin".equals(role)) {
                    sendError(session, "auth_failed", "Token role is not admin");
                    session.close(CloseStatus.NOT_ACCEPTABLE.withReason("auth_failed"));
                    return;
                }
                // register admin session
                clients.put(id, new SessionInfo(session, "admin", sub));
                session.sendMessage(new TextMessage(mapper.writeValueAsString(Map.of("type","registered","id",id,"role","admin"))));
                System.out.println("Admin registered: " + id + " (user:" + sub + ")");
                return;
            } catch (JwtException ex) {
                sendError(session, "auth_failed", "Invalid/expired token");
                session.close(CloseStatus.NOT_ACCEPTABLE.withReason("auth_failed"));
                return;
            }
        } else {
            // guest/user registration: no auth required
            // role may be "guest" or "user" depending on msg
            String actualRole = "guest";
            clients.put(id, new SessionInfo(session, actualRole, null));
            session.sendMessage(new TextMessage(mapper.writeValueAsString(Map.of("type","registered","id",id,"role",actualRole))));
            System.out.println("Registered: " + id + " as " + actualRole);
        }
    }

    private void handleRelay(WebSocketSession session, Map<String,Object> msg) throws Exception {
        String to = (String) msg.get("to");
        if (to == null) { sendError(session, "bad_request", "Missing 'to'"); return; }
        SessionInfo dest = clients.get(to);
        if (dest == null || !dest.session.isOpen()) { sendError(session, "no_destination", "Destination not connected: " + to); return; }
        // Relay raw payload; assume payload already E2E encrypted if confidentiality required
        dest.session.sendMessage(new TextMessage(mapper.writeValueAsString(msg)));
    }

    private void handleAdminList(WebSocketSession session, Map<String,Object> msg) throws Exception {
        if (!isSessionAdmin(session)) {
            sendError(session, "forbidden", "admin only");
            return;
        }

        List<Map<String,Object>> list = new ArrayList<>();
        for (Map.Entry<String, SessionInfo> e : clients.entrySet()) {
            Map<String,Object> sessionMap = new HashMap<>();
            sessionMap.put("id", e.getKey());
            sessionMap.put("role", e.getValue().role);
            sessionMap.put("username", e.getValue().username != null ? e.getValue().username : "");
            sessionMap.put("connectedSince", e.getValue().registeredAt.toString());
            list.add(sessionMap);
        }

        session.sendMessage(new TextMessage(mapper.writeValueAsString(Map.of(
                "type","admin_list_response",
                "sessions", list,
                "count", list.size()
        ))));
    }


    private boolean isSessionAdmin(WebSocketSession session) {
        return clients.values().stream().anyMatch(s -> s.session.equals(session) && "admin".equals(s.role));
    }

    private void handleAdminSend(WebSocketSession session, Map<String,Object> msg) throws Exception {
        if (!isSessionAdmin(session)) {
            sendError(session, "forbidden", "admin only");
            return;
        }
        String to = (String) msg.get("to");
        if (to == null) { sendError(session, "bad_request", "Missing 'to'"); return; }
        SessionInfo dest = clients.get(to);
        if (dest == null || !dest.session.isOpen()) { sendError(session, "no_destination", "Destination not connected: " + to); return; }
        dest.session.sendMessage(new TextMessage(mapper.writeValueAsString(msg)));
    }

    private void sendError(WebSocketSession session, String code, String message) throws Exception {
        session.sendMessage(new TextMessage(mapper.writeValueAsString(Map.of("type","error","code",code,"message",message))));
    }
}