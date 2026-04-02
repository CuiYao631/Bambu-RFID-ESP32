#include <SPI.h>
#include <Adafruit_PN532.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

// PN532 SPI 针脚定义
#define PN532_SS 5
Adafruit_PN532 pn532(PN532_SS);

// ============ 拓竹 RFID 密钥生成参数 ============
static const uint8_t HKDF_SALT[16] = {
    0x9a, 0x75, 0x9c, 0xf2, 0xc4, 0xf7, 0xca, 0xff,
    0x22, 0x2c, 0xb9, 0x76, 0x9b, 0x41, 0xbc, 0x96
};
static const uint8_t INFO_A[7] = {'R', 'F', 'I', 'D', '-', 'A', 0x00};
// static const uint8_t INFO_B[7] = {'R', 'F', 'I', 'D', '-', 'B', 0x00}; // 如需 KeyB 可取消注释

static uint8_t keysA[16 * 6]; // 16 个扇区的 KeyA，每扇区 6 字节

// 提取指定扇区的密钥
static inline void getSectorKey(uint8_t sector, uint8_t key[6]) {
    memcpy(key, &keysA[sector * 6], 6);
}

// 小端序读取 16 位无符号整数
static inline uint16_t readUint16LE(const uint8_t* buf, int offset) {
    return (uint16_t)buf[offset] | ((uint16_t)buf[offset + 1] << 8);
}

// 使用 HKDF-SHA256 派生所有扇区的密钥
static void deriveBambuKeys(const uint8_t* uid, uint8_t uidLen) {
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf(md_info, HKDF_SALT, sizeof(HKDF_SALT),
                 uid, uidLen, INFO_A, sizeof(INFO_A), keysA, sizeof(keysA));
}

// 解析扇区 1：颜色、重量、直径、烘干与打印温度 (Block 5, Block 6)
static void parseSector1(uint8_t* uid, uint8_t uidLen) {
    uint8_t key[6], data[16];
    getSectorKey(1, key);

    if (!pn532.mifareclassic_AuthenticateBlock(uid, uidLen, 5, 0, key)) {
        Serial.println("读取失败: 扇区 1 认证未通过");
        return;
    }

    if (pn532.mifareclassic_ReadDataBlock(5, data)) {
        Serial.printf("颜色 (RGBA): #%02X%02X%02X%02X\n", data[0], data[1], data[2], data[3]);
        Serial.printf("耗材重量: %u 克\n", readUint16LE(data, 4));

        // ESP32 为小端序，直接内存拷贝解析 float
        float diameter;
        memcpy(&diameter, &data[8], sizeof(float));
        Serial.printf("耗材直径: %.3f 毫米\n", diameter);
    }

    if (pn532.mifareclassic_ReadDataBlock(6, data)) {
        Serial.printf("烘干温度: %u ℃\n",     readUint16LE(data, 0));
        Serial.printf("烘干时间: %u 小时\n",   readUint16LE(data, 2));
        Serial.printf("喷嘴最高温度: %u ℃\n", readUint16LE(data, 8));
        Serial.printf("喷嘴最低温度: %u ℃\n", readUint16LE(data, 10));
    }
}

// 解析扇区 3：生产日期 (Block 12)
static void parseSector3(uint8_t* uid, uint8_t uidLen) {
    uint8_t key[6], data[16];
    getSectorKey(3, key);

    if (!pn532.mifareclassic_AuthenticateBlock(uid, uidLen, 12, 0, key)) {
        Serial.println("读取失败: 扇区 3 认证未通过");
        return;
    }

    if (pn532.mifareclassic_ReadDataBlock(12, data)) {
        char prodDate[17];
        memcpy(prodDate, data, 16);
        prodDate[16] = '\0';
        for (int i = 0; i < 16; i++) {
            if (prodDate[i] == '_') prodDate[i] = '-';
        }
        Serial.printf("生产日期: %s\n", prodDate);
    }
}

void setup() {
    Serial.begin(115200);
    delay(100); // 等待串口稳定

    pn532.begin();
    uint32_t versiondata = pn532.getFirmwareVersion();
    if (!versiondata) {
        Serial.println("未找到 PN532 模块！");
        while (1);
    }
    Serial.printf("PN532 固件版本: %d.%d\n",
                  (versiondata >> 16) & 0xFF, (versiondata >> 8) & 0xFF);
    pn532.SAMConfig();
    Serial.println("等待放置 Bambu 耗材标签...");
}

void loop() {
    uint8_t uid[7] = {};
    uint8_t uidLength;

    if (pn532.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength) && uidLength == 4) {
        Serial.println("\n==================================");
        Serial.println("读取到 Bambu 标签，正在解析...");

        deriveBambuKeys(uid, uidLength);
        parseSector1(uid, uidLength);
        parseSector3(uid, uidLength);

        Serial.println("==================================");
        delay(3000); // 避免重复读卡
    }
}