package com.tp3.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fenetre glissante par IP, appliquee uniquement a POST /auth/login.
 * Limites connues : memoire locale (pas de cluster), IP lue via getRemoteAddr()
 * (derriere un proxy, configurer server.forward-headers-strategy).
 */
public class RateLimitFilter extends OncePerRequestFilter {
    private final int max;
    private final long windowMs;
    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    public RateLimitFilter(int max, long windowMs) {
        this.max = max;
        this.windowMs = windowMs;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equals(request.getMethod()) && "/auth/login".equals(request.getRequestURI()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        long now = System.currentTimeMillis();
        Deque<Long> q = hits.computeIfAbsent(req.getRemoteAddr(), k -> new ArrayDeque<>());
        boolean allowed;
        long retryAfterSeconds = 0;
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() >= windowMs) {
                q.pollFirst();
            }
            if (q.size() >= max) {
                allowed = false;
                retryAfterSeconds = (windowMs - (now - q.peekFirst()) + 999) / 1000;
            } else {
                q.addLast(now);
                allowed = true;
            }
        }
        if (!allowed) {
            res.setStatus(429);
            res.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"Trop de tentatives, reessayez plus tard\"}");
            return;
        }
        chain.doFilter(req, res);
    }
}
