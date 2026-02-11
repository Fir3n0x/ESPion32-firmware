#include "BleManager.h"


#define PROFILE_NUM      1
#define PROFILE_APP_IDX  0
#define DEVICE_NAME      "GoPro 8690"
#define ESP_APP_ID       0x55
#define SVC_INST_ID      0

#define ADV_CONFIG_FLAG             (1 << 0)
#define SCAN_RSP_CONFIG_FLAG        (1 << 1)

static const char* TAG = "BleManager";


// Handles static
uint16_t service_handle = 0;
static uint16_t cmd_handle = 0;
static uint16_t status_handle = 0;
static uint16_t cccd_handle = 0;

static uint8_t adv_config_done = 0;
static esp_gatt_if_t gatt_if_global = ESP_GATT_IF_NONE;
static uint16_t conn_id_global = 0xFFFF;  // Use 0xFFFF as "not connected"
static bool client_connected = false;

// Handle MAC addresses
#define MAX_SEEN_MACS 256

static char seen_macs[MAX_SEEN_MACS][18];
static int seen_count = 0;

static bool mac_already_seen(const char *mac)
{
    for (int i = 0; i < seen_count; i++) {
        if (strcmp(seen_macs[i], mac) == 0) {
            return true;
        }
    }
    return false;
}

static void add_seen_mac(const char *mac)
{
    if (seen_count < MAX_SEEN_MACS) {
        strncpy(seen_macs[seen_count], mac, 18);
        seen_count++;
    }
}

void reset_mac() {
    seen_count = 0;
    memset(seen_macs, 0, sizeof(seen_macs));
    ESP_LOGI(TAG, "MAC varibles have been reset");
}


// UUIDs 128 bits LSB first
static const uint8_t SERVICE_UUID[16] = {
    0x4b, 0x91, 0x31, 0xc3,
    0xc9, 0xc5,
    0xcc, 0x8f,
    0x9e, 0x45,
    0xb5, 0x1f, 0x01, 0xc2, 0xaf, 0x4f
};

static const uint8_t CMD_UUID[16] = {
    0xa8, 0x26, 0x1b, 0x36,
    0x07, 0xea,
    0xf5, 0xb7,
    0x88, 0x46,
    0xe1, 0x36, 0x3e, 0x48, 0xb5, 0xbe
};

static const uint8_t STATUS_UUID[16] = {
    0x23, 0x11, 0x9c, 0x4f,
    0x6b, 0xbc,
    0x58, 0x8f,
    0x3f, 0x4d,
    0x12, 0x7a, 0x3a, 0x2d, 0x8c, 0x9d
};


// adv data
static esp_ble_adv_data_t adv_data = {
    .set_scan_rsp = false,
    .include_name = true,
    .include_txpower = true,
    .min_interval = 0x0006,
    .max_interval = 0x0010,
    .appearance = 0x00,
    .manufacturer_len = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data =  NULL, //&test_manufacturer[0],
    .service_data_len = 0,
    .p_service_data = NULL,
    .service_uuid_len = sizeof(SERVICE_UUID),
    .p_service_uuid = (uint8_t*)SERVICE_UUID,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

// scan response data
static esp_ble_adv_data_t scan_rsp_data = {
    .set_scan_rsp        = true,
    .include_name        = true,
    .include_txpower     = true,
    .min_interval        = 0x0006,
    .max_interval        = 0x0010,
    .appearance          = 0x00,
    .manufacturer_len    = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data = NULL, //&test_manufacturer[0],
    .service_data_len    = 0,
    .p_service_data      = NULL,
    .service_uuid_len    = sizeof(SERVICE_UUID),
    .p_service_uuid      = (uint8_t*)SERVICE_UUID,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

// Advertising parameters
static esp_ble_adv_params_t adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};



// GAP callback
static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
            adv_config_done &= (~ADV_CONFIG_FLAG);
            if (adv_config_done == 0) {
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
            
        case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
            adv_config_done &= (~SCAN_RSP_CONFIG_FLAG);
            if (adv_config_done == 0) {
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
            
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(TAG, "Advertising start failed");
            } else {
                ESP_LOGI(TAG, "Advertising started");
            }
            break;
            
        default:
            break;
    }
}

// GATT callback
static void gatts_event_handler(esp_gatts_cb_event_t event,
                                esp_gatt_if_t gatts_if,
                                esp_ble_gatts_cb_param_t *param)
{
    switch (event) {

        case ESP_GATTS_REG_EVT: {
            ESP_LOGI(TAG, "GATT server registered");
            gatt_if_global = gatts_if;

            esp_ble_gap_set_device_name(DEVICE_NAME);
            esp_ble_gap_config_adv_data(&adv_data);
            esp_ble_gap_config_adv_data(&scan_rsp_data);

            esp_gatt_srvc_id_t service_id = {
                .is_primary = true,
                .id = {
                    .uuid = {
                        .len = ESP_UUID_LEN_128,
                        .uuid.uuid128 = {0}
                    },
                    .inst_id = 0
                }
            };
            memcpy(service_id.id.uuid.uuid.uuid128, SERVICE_UUID, 16);

            esp_ble_gatts_create_service(gatt_if_global, &service_id, 10);
            break;
        }

        case ESP_GATTS_CREATE_EVT:
            ESP_LOGI(TAG, "Service created, handle=%d", param->create.service_handle);
            service_handle = param->create.service_handle;

            // Start Service
            ESP_LOGI(TAG, "Starting service...");
            esp_ble_gatts_start_service(service_handle);

            // Add CMD characteristic (WRITE)
            esp_bt_uuid_t cmd_uuid = {
                .len = ESP_UUID_LEN_128,
                .uuid.uuid128 = {0}
            };
            memcpy(cmd_uuid.uuid.uuid128, CMD_UUID, 16);

            esp_ble_gatts_add_char(service_handle, &cmd_uuid,
                                   ESP_GATT_PERM_WRITE,
                                   ESP_GATT_CHAR_PROP_BIT_WRITE,
                                   NULL, NULL);
            break;

        case ESP_GATTS_ADD_CHAR_EVT:
            ESP_LOGI(TAG, "Characteristic added, handle=%d, uuid=%x",
                     param->add_char.attr_handle,
                     param->add_char.char_uuid.uuid.uuid16);

            // First added char is CMD
            if (cmd_handle == 0) {
                cmd_handle = param->add_char.attr_handle;
                
                // Now add STATUS characteristic
                esp_bt_uuid_t status_uuid = {
                    .len = ESP_UUID_LEN_128,
                };
                memcpy(status_uuid.uuid.uuid128, STATUS_UUID, 16);

                esp_ble_gatts_add_char(service_handle, &status_uuid,
                                       ESP_GATT_PERM_READ,
                                       ESP_GATT_CHAR_PROP_BIT_NOTIFY,
                                       NULL, NULL);
            } else {
                // Second added char is STATUS
                status_handle = param->add_char.attr_handle;
                ESP_LOGI(TAG, "STATUS characteristic handle: %d", status_handle);

                // Add CCCD for STATUS characteristic
                esp_bt_uuid_t cccd_uuid = {
                    .len = ESP_UUID_LEN_16,
                    .uuid.uuid16 = ESP_GATT_UUID_CHAR_CLIENT_CONFIG,
                };

                esp_ble_gatts_add_char_descr(service_handle, &cccd_uuid,
                                             ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                             NULL, NULL);
            }

            break;

        case ESP_GATTS_ADD_CHAR_DESCR_EVT:
            cccd_handle = param->add_char_descr.attr_handle;

            break;

        case ESP_GATTS_START_EVT:
            ESP_LOGI(TAG, "Service started");
            break;

        case ESP_GATTS_CONNECT_EVT:
            ESP_LOGI(TAG, "Client connected, conn_id=%d", param->connect.conn_id);
            conn_id_global = param->connect.conn_id;
            gatt_if_global = gatts_if;
            client_connected = true;
            // blink
            bleClientConnected();
            break;

        case ESP_GATTS_DISCONNECT_EVT:
            ESP_LOGI(TAG, "Client disconnected, reason=0x%02x", param->disconnect.reason);
            conn_id_global = 0xFFFF;
            client_connected = false;
            esp_ble_gap_start_advertising(&adv_params);
            // Reset wifi variables and stop all attacks
            onBleDisconnect();
            // blink
            bleClientDisconnected();
            break;

        case ESP_GATTS_WRITE_EVT:

            ESP_LOGI(TAG, "WRITE_EVT handle=%d, need_rsp=%d, is_prep=%d",
                     param->write.handle, param->write.need_rsp, param->write.is_prep);

            // CRITICAL: Send response for CCCD and CMD writes
            if (param->write.need_rsp) {
                esp_ble_gatts_send_response(gatts_if, 
                                           param->write.conn_id,
                                           param->write.trans_id,
                                           ESP_GATT_OK,
                                           NULL);
                ESP_LOGI(TAG, "Write response sent");
            }

            if (param->write.handle == cmd_handle) {
                // Safely handle command
                char cmd[384] = {0};
                size_t len = param->write.len < sizeof(cmd) - 1 ? param->write.len : sizeof(cmd) - 1;
                memcpy(cmd, param->write.value, len);
                cmd[len] = '\0';
                
                ESP_LOGI(TAG, "CMD received: %s", cmd);
                
                // Blink when command received
                receiveCommandBlink();

                // Process commands
                handle_command(cmd);
            }
            
            break;

        default:
            break;
    }
}


void BleManager_SendStatus(const char *msg) {
    ESP_LOGI(TAG, "SendStatus: msg='%s', connected=%d, conn_id=%d, gatt_if=%d, handle=%d",
             msg, client_connected, conn_id_global, gatt_if_global, status_handle);
    
    if (!client_connected || gatt_if_global == ESP_GATT_IF_NONE) {
        ESP_LOGW(TAG, "No client connected, message dropped");
        return;
    }

    if (status_handle == 0) {
        ESP_LOGE(TAG, "STATUS handle not initialized!");
        return;
    }

    uint16_t len = strlen(msg);
    esp_err_t ret = esp_ble_gatts_send_indicate(gatt_if_global, conn_id_global,
                                                status_handle, len,
                                                (uint8_t*)msg, false);
    
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Status sent: %s", msg);
    } else {
        ESP_LOGE(TAG, "Send indicate failed: %s (0x%x)", esp_err_to_name(ret), ret);
    }
}

// BLE Sender Task
void bleSenderTask(void* param) {
    mac_event_t evt;

    while (true) {
        if (xQueueReceive(macQueue, &evt, portMAX_DELAY)) {

            if (!client_connected) continue;

            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                    evt.mac[0], evt.mac[1], evt.mac[2],
                    evt.mac[3], evt.mac[4], evt.mac[5]);


            if (mac_already_seen(macStr)) continue;

            add_seen_mac(macStr);

            char payload[64];
            snprintf(payload, sizeof(payload),
                "MAC|SNIFF|mac=%s|rssi=%d|ch=%d",
                macStr, evt.rssi, evt.channel);

            ESP_LOGI(TAG, "BLE NOTIFY: %s", payload);

            esp_err_t err = esp_ble_gatts_send_indicate(
                gatt_if_global,
                conn_id_global,
                status_handle,
                strlen(payload),
                (uint8_t*)payload,
                false
            );

            if(err != ESP_OK) {
                ESP_LOGE(TAG, "Notify failed: %s", esp_err_to_name(err));
            }
        }
        // if not -> tempo
        else {
            vTaskDelay(pdMS_TO_TICKS(500));
        }
    }
}

void BleManager_Init()
{

    esp_err_t ret;

    ESP_LOGI(TAG, "Initializing BLE...");

    // Initialize Bluetooth controller
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(TAG, "%s initialize controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(TAG, "%s enable controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(TAG, "%s init bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(TAG, "%s enable bluetooth failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(TAG, "gatts register error, error code = %x", ret);
        return;
    }

    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(TAG, "gap register error, error code = %x", ret);
        return;
    }

    
    ret = esp_ble_gatts_app_register(PROFILE_APP_IDX);
    if (ret){
        ESP_LOGE(TAG, "gatts app register error, error code = %x", ret);
        return;
    }

    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(384);
    if (local_mtu_ret){
        ESP_LOGE(TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }

    ESP_LOGI(TAG, "Bluetooth initialized successfully");
}