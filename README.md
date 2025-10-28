diff --git a/README.md b/README.md
index eb49b606e2a5b318e0634052e61abd6c971e9c42..8fd7c78aba860dc1ad9113f5d7fac9ad06e93baf 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,15 @@
 # AI_TRA_1
+
 AI TRAINING SIMPLE CODES
+
+## Gürültülü Sinüs Dalgası Tahmini
+
+`python sine_wave_regression.py` komutunu çalıştırarak aşağıdaki adımlar otomatik olarak gerçekleştirilir:
+
+1. Sinüs dalgası oluşturulur ve üzerine rastgele gürültü eklenir.
+2. Gürültülü veri için lineer regresyon ve RBF çekirdekli SVR modelleri eğitilir.
+3. Modellerin tahminleri, gerçek sinüs dalgası ve gürültülü gözlemlerle birlikte grafikte gösterilir.
+4. Her model için ortalama kare hata (MSE) hesaplanır ve terminale yazdırılır.
+5. Oluşturulan grafik `figures/sine_regression.png` dosyasına kaydedilir.
+
+Gerekli bağımlılıklar: `numpy`, `matplotlib` ve `scikit-learn`.
