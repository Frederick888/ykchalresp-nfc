#include <nfc/nfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHALLENGE_LENGTH 64
// copied from ykcore/ykdef.h in yubikey-personalization
#define SLOT_CHAL_HMAC1 0x30
#define SLOT_CHAL_HMAC2 0x38

int verbose = 0;

int card_transmit(nfc_device *pnd, uint8_t *capdu, size_t capdulen, uint8_t *rapdu, size_t *rapdulen) {
    int res;
    if (verbose) {
        size_t pos;
        fprintf(stderr, "=> ");
        for (pos = 0; pos < capdulen; pos++) fprintf(stderr, "%02x ", capdu[pos]);
        fprintf(stderr, "\n");
    }
    if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdulen, rapdu, *rapdulen, 500)) < 0) {
        return -1;
    } else {
        *rapdulen = (size_t)res;
        if (verbose) {
            size_t pos;
            fprintf(stderr, "<= ");
            for (pos = 0; pos < *rapdulen; pos++) fprintf(stderr, "%02x ", rapdu[pos]);
            fprintf(stderr, "\n");
        }
        return 0;
    }
}

int send_apdu(nfc_device *pnd, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t *data, uint8_t data_len,
              uint8_t *resp, size_t *resp_len) {
    uint8_t *msg = malloc(4 + 1 + data_len);
    int ret;
    msg[0] = cla;
    msg[1] = ins;
    msg[2] = p1;
    msg[3] = p2;
    msg[4] = data_len;
    memcpy(&msg[5], data, data_len);
    ret = card_transmit(pnd, msg, 4 + 1 + data_len, resp, resp_len);
    free(msg);
    if (ret != 0) return ret;
    if (*resp_len < 2 || resp[*resp_len - 2] != 0x90 || resp[*resp_len - 1] != 0x00) {
        return -1;
    }
    return ret;
}

int main(int argc, char *argv[]) {
    uint8_t slot;
    int opt;
    while ((opt = getopt(argc, argv, "12v")) != -1) {
        switch (opt) {
            case '1':
                slot = SLOT_CHAL_HMAC1;
                break;
            case '2':
                slot = SLOT_CHAL_HMAC2;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                slot = SLOT_CHAL_HMAC2;
        }
    }

    char challenge[MAX_CHALLENGE_LENGTH + 1];
    uint8_t challenge_len;
    memset(challenge, '\0', MAX_CHALLENGE_LENGTH + 1);
    if (optind >= argc) {
        char *ret;
        ret = fgets(challenge, MAX_CHALLENGE_LENGTH, stdin);
        if (ret == NULL) {
            exit(EXIT_FAILURE);
        }
        ret = strrchr(challenge, '\n');
        if (ret != NULL) {
            *ret = '\0';
        }
    } else {
        strncpy(challenge, argv[optind], MAX_CHALLENGE_LENGTH);
    }
    challenge_len = strlen(challenge);

    nfc_device *pnd;
    nfc_context *context;
    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }
    if (verbose) {
        const char *acLibnfcVersion = nfc_version();
        fprintf(stderr, "%s uses libnfc %s\n", argv[0], acLibnfcVersion);
    }
    pnd = nfc_open(context, NULL);

    if (pnd == NULL) {
        fprintf(stderr, "ERROR: %s", "Unable to open NFC device.\n");
        exit(EXIT_FAILURE);
    }
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }
    if (verbose) fprintf(stderr, "NFC reader: %s opened\n", nfc_device_get_name(pnd));

    const nfc_modulation nmMifare = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };
    nfc_target ant[1];
    if (nfc_initiator_list_passive_targets(pnd, nmMifare, ant, 1) < 1) {
        fprintf(stderr, "YubiKey not found\n");
        exit(EXIT_FAILURE);
    }

    uint8_t msg[264];
    size_t msg_len;
    uint8_t resp[264];
    size_t resp_len;

    // Select application
    memcpy(msg, "\xA0\x00\x00\x05\x27\x20\x01", 7);
    msg_len = 7;
    resp_len = sizeof(resp);
    if (send_apdu(pnd, 0x00, 0xA4, 0x04, 0x00, msg, msg_len, resp, &resp_len) < 0) exit(EXIT_FAILURE);

    // Challenge Response
    memcpy(msg, challenge, challenge_len);
    msg_len = challenge_len;
    resp_len = sizeof(resp);
    if (send_apdu(pnd, 0x00, 0x01, slot, 0x00, msg, msg_len, resp, &resp_len) < 0) exit(EXIT_FAILURE);
    if (resp_len <= 2) {
        fprintf(stderr, "Empty response\n");
        exit(EXIT_FAILURE);
    }

    size_t pos;
    for (pos = 0; pos < resp_len - 2; pos++) printf("%02x", resp[pos]);
    printf("\n");

    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_SUCCESS);
}