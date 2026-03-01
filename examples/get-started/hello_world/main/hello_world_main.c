/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"

void vBlinkTask(void *pvParameters) {
        static uint32_t count = 0;
    while(1) {
        // Toggle LED here
        if(count % 100 == 0){
           printf("%u\n", count);
           fflush(stdout);
        }
        count++;
        vTaskDelay(10 / portTICK_RATE_MS); // 10ms delay
    }
}

void app_main()
{

    printf("Hello world! tick timer = %u\n", portTICK_RATE_MS);

    xTaskCreate(&vBlinkTask, "blink_task", 2048, NULL, 5, NULL);    
    
    static uint32_t main_count = 0;
    while(1)
    {
        
        esp_set_cpu_freq(ESP_CPU_FREQ_160M);
        /* Print chip information */
        esp_chip_info_t chip_info;
        esp_chip_info(&chip_info);
        printf("This is ESP8266 chip with %d CPU cores, WiFi,  %s ",
                chip_info.cores, chip_info.features & CHIP_FEATURE_BT ? "BT" : "no BT"  );

        printf("silicon revision %d, ", chip_info.revision);

        printf("%dMB %s flash count = %d\n", spi_flash_get_chip_size() / (1024 * 1024),
                (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external", main_count++);

        //for (int i = 10; i >= 0; i--) {
        //    printf("Restarting in %d seconds...\n", i);
        //    vTaskDelay(1000 / portTICK_PERIOD_MS);
        //}
        //printf("Restarting now.\n");
        fflush(stdout);
        //esp_restart();
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}
