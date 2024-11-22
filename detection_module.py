class DDoSDetector:
    def __init__(self, model):
        self.model = model
    
    def detect(self, features):
        # Chuyển đổi đặc trưng thành định dạng mà mô hình có thể nhận
        prediction = self.model.predict(features)
        return prediction == 1  # Nếu là tấn công DDoS, trả về True

