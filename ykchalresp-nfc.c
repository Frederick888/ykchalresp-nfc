#include "cmdline.h"
#include <nfc/nfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHALLENGE_LENGTH 64
// copied from ykcore/ykdef.h in yubikey-personalization
#define SLOT_CHAL_HMAC1 0x30
#define SLOT_CHAL_HMAC2 0x38

#define vlog(f_, ...) \
    if (verbose)      \
    fprintf(stderr, (f_), ##__VA_ARGS__)
#define elog(f_, ...) fprintf(stderr, (f_), ##__VA_ARGS__)

int verbose = 0;

int card_transmit(nfc_device *pnd, uint8_t *capdu, size_t capdu_len, uint8_t *rapdu, size_t *rapdu_len) {
    int res;
    if (verbose) {
        size_t pos;
        vlog("=> ");
        for (pos = 0; pos < capdu_len; pos++)
            vlog("%02x ", capdu[pos]);
        vlog("\n");
    }
    if ((res = nfc_initiator_transceive_bytes(pnd, capdu, capdu_len, rapdu, *rapdu_len, 500)) < 0) {
        return -1;
    } else {
        *rapdu_len = (size_t)res;
        if (verbose) {
            size_t pos;
            vlog("<= ");
            for (pos = 0; pos < *rapdu_len; pos++)
                vlog("%02x ", rapdu[pos]);
            vlog("\n");
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
    if (ret != 0)
        return ret;
    if (*resp_len < 2 || resp[*resp_len - 2] != 0x90 || resp[*resp_len - 1] != 0x00) {
        return -1;
    }
    return ret;
}

int main(int argc, char *argv[]) {
    uint8_t slot;
    int dry_run;
    struct gengetopt_args_info args_info;
    if (cmdline_parser(argc, argv, &args_info) != 0)
        exit(EXIT_FAILURE);
    slot = args_info.slot_1_given ? 2 : 1;
    dry_run = args_info.dry_run_given;
    verbose = args_info.verbose_given;

    char challenge[MAX_CHALLENGE_LENGTH + 1];
    uint8_t challenge_len;
    if (!dry_run) {
        memset(challenge, '\0', MAX_CHALLENGE_LENGTH + 1);
        if (!args_info.inputs_num) {
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
            strncpy(challenge, args_info.inputs[0], strlen(args_info.inputs[0]));
        }
        challenge_len = strlen(challenge);
    }

    nfc_device *pnd;
    nfc_context *context;
    nfc_init(&context);
    if (context == NULL) {
        elog("ERROR: %s\n", "Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }
    if (verbose) {
        const char *libnfc_version = nfc_version();
        vlog("DEBUG: ykchalresp-nfc uses libnfc %s\n", libnfc_version);
    }
    pnd = nfc_open(context, NULL);

    if (pnd == NULL) {
        elog("ERROR: %s\n", "Unable to open NFC device");
        exit(EXIT_FAILURE);
    }
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }
    vlog("DEBUG: NFC reader %s opened\n", nfc_device_get_name(pnd));

    const nfc_modulation nmMifare = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };
    nfc_target ant[1];
    if (nfc_initiator_list_passive_targets(pnd, nmMifare, ant, 1) < 1) {
        elog("ERROR: %s\n", "YubiKey not found");
        exit(EXIT_FAILURE);
    }

    if (dry_run) {
        goto cleanup;
    }

    uint8_t msg[264];
    size_t msg_len;
    uint8_t resp[264];
    size_t resp_len;

    // Select application
    memcpy(msg, "\xA0\x00\x00\x05\x27\x20\x01", 7);
    msg_len = 7;
    resp_len = sizeof(resp);
    if (send_apdu(pnd, 0x00, 0xA4, 0x04, 0x00, msg, msg_len, resp, &resp_len) < 0)
        exit(EXIT_FAILURE);

    // Challenge Response
    memcpy(msg, challenge, challenge_len);
    msg_len = challenge_len;
    resp_len = sizeof(resp);
    if (send_apdu(pnd, 0x00, 0x01, slot, 0x00, msg, msg_len, resp, &resp_len) < 0)
        exit(EXIT_FAILURE);
    if (resp_len <= 2) {
        elog("ERROR: %s\n", "Empty response");
        exit(EXIT_FAILURE);
    }

    size_t pos;
    for (pos = 0; pos < resp_len - 2; pos++)
        printf("%02x", resp[pos]);
    printf("\n");

cleanup:
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_SUCCESS);
}
