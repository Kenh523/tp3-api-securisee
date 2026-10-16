# Note de conception – TP3 : sécurisation d'une API REST

## Contexte
API de gestion de notes personnelles (`/notes`) + point d'authentification (`/auth/login`).
Départ : API ouverte. Arrivée : API authentifiée, autorisée, validée et limitée.

## Menaces traitées

| # | Menace | Contre-mesure | Où | Test |
|---|--------|---------------|----|------|
| 1 | Accès anonyme aux données | Toute route sauf `/auth/login` exige un jeton (`anyRequest().authenticated()`) | `SecurityConfig` | `anonyme_recoit_401` |
| 2 | Jeton falsifié / signature forgée | Signature HS256 vérifiée, algorithme imposé (pas de `alg: none`) | `jwtDecoder` | `mauvaise_signature_refusee` |
| 3 | Rejeu d'un vieux jeton | Expiration (`exp`) vérifiée, durée de vie 15 min | `JwtValidators` | `jeton_expire_refuse` |
| 4 | Jeton émis par un autre service | Émetteur (`iss`) et audience (`aud`) vérifiés | `JwtValidators` + `AudienceValidator` | `mauvais_emetteur_refuse`, `mauvaise_audience_refusee` |
| 5 | Élévation de privilèges | Rôles dans le claim `roles`, contrôlés par `@PreAuthorize` | `NoteController` | `utilisateur_sans_droit_recoit_403` |
| 6 | BOLA / IDOR (lire ou modifier l'objet d'un autre) | Vérification du propriétaire dans la couche service, propriétaire pris dans `sub` du jeton | `NoteService.getOwned` | `utilisateur_ne_peut_pas_lire_lobjet_dun_autre_BOLA` |
| 7 | Mass assignment / sur-exposition | DTO d'entrée sans `id`/`owner`, DTO de sortie sans `owner` | `NoteRequest`, `NoteResponse` | `mass_assignment_ignore_owner...`, `proprietaire_lit_sa_note_sans_voir_le_champ_owner` |
| 8 | Entrées malformées / trop grosses | Bean Validation (`@NotBlank`, `@Size`) + `@Valid` ; réponse 400 sans détail interne | DTO + `ApiExceptionHandler` | `titre_vide_donne_400` |
| 9 | Force brute sur le login | Limitation 5 req / 60 s / IP (429 + `Retry-After`) | `RateLimitFilter` | `RateLimitTest` |
| 10 | Énumération de comptes | Message unique « Identifiants invalides » ; mots de passe hachés BCrypt | `AuthController` | `login_invalide_donne_401` |
| 11 | Fuite d'informations par les erreurs | `server.error.include-message/stacktrace=never` | `application.properties` | – |
| 12 | Secret en dur | Secret JWT et mot de passe de démo lus depuis l'environnement, sans valeur par défaut dans le code (démarrage refusé si absents ou si secret < 32 octets) ; valeurs factices isolées dans `src/test/resources` | `application.properties`, `SecurityConfig` | – |

## Décisions de conception
- **CSRF désactivé** : API sans session ni cookie, authentification par en-tête `Authorization`.
- **Sans état** (`STATELESS`) : aucun `HttpSession`.
- **Autorisation à deux niveaux** : *rôle* (`@PreAuthorize`, grossier) puis *propriété de l'objet* (service, fin). Le rôle seul ne suffit pas contre BOLA.
- **403 plutôt que 404** pour l'objet d'un autre : explicite pour le TP. Variante plus discrète : renvoyer 404 pour ne pas révéler l'existence de l'objet.
- **ADMIN** : lecture/modification de toutes les notes et seul rôle autorisé à supprimer.

## Limites connues / pistes
- HS256 (secret partagé) : en production, préférer RS256/ES256 avec clé publique côté API ; rotation de clés via `kid`.
- Pas de révocation de jeton ni de refresh token (durée de vie courte à la place).
- Le limiteur compte toutes les tentatives sur `/auth/login` (réussies ou non) et ne purge jamais sa table d'adresses IP : à compléter par un nettoyage périodique ou un compteur d'échecs seulement.
- Limiteur en mémoire locale : à remplacer par Redis/Bucket4j en cluster ; IP lue par `getRemoteAddr()` (configurer `forward-headers-strategy` derrière un proxy).
- Utilisateurs en mémoire : à remplacer par une base avec politique de mots de passe et verrouillage de compte.
- HTTPS obligatoire en production (TLS terminé par le serveur ou un reverse proxy).
