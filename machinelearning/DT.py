from datetime import datetime
from matplotlib import pyplot as plt
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score, mean_squared_error
from sklearn.model_selection import cross_val_score
# Recall
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
# AUC
from sklearn.metrics import roc_auc_score

import itertools
class MachineLearning():

    def __init__(self):
        
        print("Loading dataset ...")
        
        self.flow_dataset = pd.read_csv('FlowStatsfile.csv')

        self.flow_dataset.iloc[:, 2] = self.flow_dataset.iloc[:, 2].str.replace('.', '')
        self.flow_dataset.iloc[:, 3] = self.flow_dataset.iloc[:, 3].str.replace('.', '')
        self.flow_dataset.iloc[:, 5] = self.flow_dataset.iloc[:, 5].str.replace('.', '')   

    def flow_training(self):

        print("Flow Training ...")
        
        X_flow = self.flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = self.flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        classifier = DecisionTreeClassifier(criterion='entropy', random_state=0)
        flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = flow_model.predict(X_flow_test)

        print("------------------------------------------------------------------------------")

        print("confusion matrix")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        print(cm)

        acc = accuracy_score(y_flow_test, y_flow_pred)

        print("success accuracy = {0:.2f} %".format(acc*100))
        print("Precision score = {0:.2f} %".format(precision_score(y_flow_test, y_flow_pred)*100))
        print("Recall score = {0:.2f} %".format(recall_score(y_flow_test, y_flow_pred)*100))
        print("F1 score = {0:.2f} %".format(f1_score(y_flow_test, y_flow_pred)*100))
        print("cross-validation score = {0:.2f} %".format(cross_val_score(classifier, X_flow, y_flow, cv=10).mean()*100))
        print("AUC score = {0:.2f} %".format(roc_auc_score(y_flow_test, y_flow_pred)*100))
        print("------------------------------------------------------------------------------")
        # Hien thi bao nhieu du lieu train, ba nhieu du lieu test voi moi class
        # Train class 0
        print("Train class 0: ", len(y_flow_train[y_flow_train == 0]))
        # # Train class 1
        print("Train class 1: ", len(y_flow_train[y_flow_train == 1]))
        # # Test class 0
        print("Test class 0: ", len(y_flow_test[y_flow_test == 0]))
        # # Test class 1
        print("Test class 1: ", len(y_flow_test[y_flow_test == 1]))
        print("------------------------------------------------------------------------------")

        # Vẽ ma trận nhầm lẫn 2x2
        # Truc x la True Data, truc y la Predicted Data
        '''
        TP FP
        FN TN
        '''
        plt.figure()
        plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        plt.title('Confusion matrix')
        plt.colorbar()
        tick_marks = np.arange(2)
        plt.xticks(tick_marks, ['Normal', 'DDoS'], rotation=45)
        plt.yticks(tick_marks, ['Normal', 'DDoS'])
        thresh = cm.max() / 2.
        for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
            plt.text(j, i, cm[i, j], horizontalalignment='center', color='white' if cm[i, j] > thresh else 'black')
        plt.tight_layout()
        plt.ylabel('True label')
        plt.xlabel('Predicted label')
        plt.show()
        print("------------------------------------------------------------------------------")
        # Ve bieu do accuracy, loss
        train_acc = []
        train_loss = []
        # Vòng lặp huấn luyện
        for i in range(100):
            model = classifier.fit(X_flow_train, y_flow_train)
            y_pred = model.predict(X_flow_train)

            # Tính toán accuracy và loss
            acc = accuracy_score(y_flow_train, y_pred)
            loss = mean_squared_error(y_flow_train, y_pred)

            # Lưu trữ accuracy và loss
            train_acc.append(acc)
            train_loss.append(loss)

        # Ve do thi accuracy va loss trong 1 bieu do
        plt.figure()
        plt.plot(train_acc, label='Accuracy')
        plt.plot(train_loss, label='Loss')
        plt.legend()
        plt.show()
        print("------------------------------------------------------------------------------")
        # Ve duong ROC, tinh AUC
        from sklearn.metrics import roc_curve
        from sklearn.metrics import auc
        fpr, tpr, thresholds = roc_curve(y_flow_test, y_flow_pred)
        roc_auc = auc(fpr, tpr)
        plt.figure()
        plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver operating characteristic')
        plt.legend(loc='lower right')
        plt.show()
        print("------------------------------------------------------------------------------")
        # Do sau cua cay quyet dinh
        print("Tree depth: ", classifier.get_depth())
        # So nut la cua cay quyet dinh
        print("Number of leaves: ", classifier.get_n_leaves())
        # Entropy cua cay quyet dinh
        print("Entropy: ", classifier.tree_.impurity)
        # So lan split cua cay quyet dinh
        print("Number of splits: ", classifier.tree_.n_node_samples)
        print("------------------------------------------------------------------------------")
        # Ve cay quyet dinh
        from sklearn.tree import plot_tree
        plt.figure()
        plot_tree(classifier, filled=True)
        plt.show()
        print("------------------------------------------------------------------------------")
        # Thong tin chi tiet tai moi nut
        # Lay ra cac node
        node_indicator = classifier.decision_path(X_flow_test)
        # Lay ra cac feature
        feature = classifier.tree_.feature
        # Lay ra cac threshold
        threshold = classifier.tree_.threshold
        # Lay ra cac value
        value = classifier.tree_.value
        # Lay ra cac sample
        sample = classifier.tree_.n_node_samples
        # Lay ra cac impurity
        impurity = classifier.tree_.impurity
        # Lay ra cac children_left
        children_left = classifier.tree_.children_left
        # Lay ra cac children_right
        children_right = classifier.tree_.children_right
        
        # Vong lap in ra thong tin chi tiet cua moi node
        for i in range(classifier.tree_.node_count):
            if children_left[i] != children_right[i]:
                print("Node ", i)
                print("Feature: ", feature[i])
                print("Threshold: ", threshold[i])
                print("Value: ", value[i])
                print("Sample: ", sample[i])
                print("Impurity: ", impurity[i])
                print("Children left: ", children_left[i])
                print("Children right: ", children_right[i])
                print("--------------------------------------------------")
        print("------------------------------------------------------------------------------")
        # Save trong so cua mo hinh
        import pickle
        with open('model.pkl', 'wb') as file:
            pickle.dump(flow_model, file)
        print("------------------------------------------------------------------------------")
        # Load trong so cua mo hinh
        with open('model.pkl', 'rb') as file:
            model = pickle.load(file)
        print("------------------------------------------------------------------------------")

def main():
    start = datetime.now()
    
    ml = MachineLearning()
    ml.flow_training()

    end = datetime.now()
    print("Training time: ", (end-start)) 

if __name__ == "__main__":
    main()
