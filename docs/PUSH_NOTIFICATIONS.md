# Push notifications

Wormhole Observatory can forward review notifications to **ntfy** and **UnifiedPush/Web Push**. Push delivery uses the existing notification rate limiter and runs asynchronously so a slow or unavailable push service does not block classification work.

## Deep links

Set **Settings → Notifications → Review app base URL** to an address that the receiving device can reach. A notification for `example.com` links to:

`<review-base-url>?domain=example.com`

After authentication, the PWA loads that domain through the authenticated review API and opens its detail dialog directly. The API token is not embedded in the notification URL.

For another device, `localhost` is normally not useful. Use an HTTPS/LAN/Tailscale address once that access mode is configured.

## ntfy

Configure:

- server URL, for example `https://ntfy.sh` or a trusted self-hosted server;
- topic;
- optional access token.

Wormhole Observatory publishes JSON notifications and uses ntfy's `click` field for the review deep link. The access token is stored through the operating-system credential store when available.

## UnifiedPush / Web Push

Configure the registration values supplied by the receiving client/distributor:

- HTTPS push endpoint;
- `p256dh` public key;
- auth secret.

The application creates a P-256 VAPID key automatically. The private VAPID key, endpoint and auth secret are stored through the operating-system credential store when available. Payloads are encrypted as RFC 8291 Web Push (`aes128gcm`) before transmission.

By default, UnifiedPush endpoints must resolve to globally routable addresses. Private/non-global endpoints require an explicit opt-in intended for a trusted self-hosted push server.

## Testing

Use **Send test push** in the Notifications settings. A successful test confirms delivery configuration; opening it should take the client to the PWA's `example.com` detail view.

Push delivery never makes review data public: the notification contains only its title/message/domain/deep-link metadata, while all `/v1/*` review API calls remain Bearer-authenticated.
