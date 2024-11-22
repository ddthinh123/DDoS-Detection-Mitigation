import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os

class MachineLearning():
    def __init__(self):
        print("Loading dataset ...")
        
        # Kiểm tra xem file dataset.csv có tồn tại không
        if not os.path.exists('dataset.csv'):
            print("File 'dataset.csv' not found. Please ensure the file is in the correct directory.")
            return
        
        # Đọc file CSV
        self.flow_dataset = pd.read_csv('dataset.csv')

        # Loại bỏ khoảng trắng ở tên cột
        self.flow_dataset.columns = self.flow_dataset.columns.str.strip()

        # Xác định các cột cần chuyển đổi
        columns_to_convert = [
            'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 
            'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 
            'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 
            'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
            'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 
            'Bwd IAT Min', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 
            'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance'
        ]

        # Chuyển đổi cột sang kiểu số và thay thế giá trị NaN
        for col in columns_to_convert:
            if col in self.flow_dataset.columns:
                self.flow_dataset[col] = pd.to_numeric(self.flow_dataset[col], errors='coerce')
                self.flow_dataset[col] = self.flow_dataset[col].fillna(0).astype(float)

        # Xử lý NaN và giá trị vô hạn
        self.flow_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
        self.flow_dataset.dropna(inplace=True)
        
        # Tách dữ liệu thành features và labels
        self.X_flow = self.flow_dataset.iloc[:, :-1]  # Tất cả các cột trừ cột cuối
        self.y_flow = self.flow_dataset.iloc[:, -1]   # Cột cuối là nhãn

        # Chuyển nhãn 'BENIGN' và 'DDoS' thành nhị phân (0, 1)
        self.y_flow = self.y_flow.map({'BENIGN': 0, 'DDoS': 1})

        # Tách dữ liệu thành tập huấn luyện (70%) và tập kiểm tra (30%)
        self.X_flow_train, self.X_flow_test, self.y_flow_train, self.y_flow_test = train_test_split(
            self.X_flow, self.y_flow, test_size=0.3, random_state=42
        )

    def flow_training(self):
        print("Flow Training ...")
        
        # Khởi tạo mô hình Random Forest với tham số tùy chỉnh
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10, min_samples_split=5)
        
        # Huấn luyện mô hình trên dữ liệu huấn luyện
        start_time = time.time()
        self.classifier.fit(self.X_flow_train, self.y_flow_train)
        training_time = time.time() - start_time
        
        # Dự đoán trên dữ liệu kiểm tra
        y_test_pred = self.classifier.predict(self.X_flow_test)
        y_test_pred_prob = self.classifier.predict_proba(self.X_flow_test)[:, 1]  # Dự đoán xác suất cho lớp 1
        
        # Tính toán độ chính xác trên tập huấn luyện và tập kiểm tra
        train_accuracy = accuracy_score(self.y_flow_train, self.classifier.predict(self.X_flow_train))
        test_accuracy = accuracy_score(self.y_flow_test, y_test_pred)
        
        # Tính các chỉ số khác cho tập kiểm tra
        precision = precision_score(self.y_flow_test, y_test_pred)
        recall = recall_score(self.y_flow_test, y_test_pred)
        f1 = f1_score(self.y_flow_test, y_test_pred)
        cm = confusion_matrix(self.y_flow_test, y_test_pred)

        print(f"Total samples: {len(self.flow_dataset)}")
        print(f"Number of features: {self.X_flow.shape[1]}")
        
        
        print(f"Model: Random Forest")
        print(f"Parameters: {self.classifier.get_params()}")
        print(f"Training time: {training_time:.2f} seconds")
        
        print(f"Train Accuracy: {train_accuracy}")
        print(f"Test Accuracy: {test_accuracy}")
        print(f"Precision: {precision}")
        print(f"Recall: {recall}")
        print(f"F1-score: {f1}")
        print("Confusion Matrix:")
        print(cm)

        # Lưu mô hình
        try:
            with open('model.pkl', 'wb') as file:
                pickle.dump(self.classifier, file)
            print("Model has been saved to 'model.pkl'.")
        except Exception as e:
            print(f"Error saving the model: {e}")

        # Tính ROC curve và AUC
        fpr, tpr, thresholds = roc_curve(self.y_flow_test, y_test_pred_prob)
        roc_auc = auc(fpr, tpr)

        # Tạo một cửa sổ với 2 biểu đồ (1 hàng, 2 cột)
        fig, axs = plt.subplots(1, 2, figsize=(15, 6))

        # Vẽ Confusion Matrix trên biểu đồ đầu tiên
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['BENIGN', 'DDoS'], yticklabels=['BENIGN', 'DDoS'], ax=axs[0])
        axs[0].set_title('Confusion Matrix')
        axs[0].set_xlabel('Predicted Label')
        axs[0].set_ylabel('True Label')

        # Vẽ ROC Curve trên biểu đồ thứ hai
        axs[1].plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
        axs[1].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        axs[1].set_xlim([0.0, 1.0])
        axs[1].set_ylim([0.0, 1.05])
        axs[1].set_xlabel('False Positive Rate')
        axs[1].set_ylabel('True Positive Rate')
        axs[1].set_title('Receiver Operating Characteristic (ROC)')
        axs[1].legend(loc='lower right')

        # Hiển thị cả hai biểu đồ
        plt.show()


def main():
    try:
        # Khởi tạo lớp MachineLearning
        ml = MachineLearning()
        
        # Kiểm tra xem dữ liệu đã được tải thành công chưa
        if ml.flow_dataset is not None:
            # Huấn luyện mô hình
            ml.flow_training() 
    except Exception as e:
        print(f"An error occurred during execution: {e}")

if __name__ == "__main__":
    main()
