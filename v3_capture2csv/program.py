# %pip install seaborn
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split

from sklearn.preprocessing import (
    StandardScaler,
    QuantileTransformer,
    MinMaxScaler,
    Normalizer,
    RobustScaler,
    LabelEncoder,
)
from sklearn.metrics import *

from tqdm import tqdm
import matplotlib as mpl

mpl.rcParams.update(mpl.rcParamsDefault)


np.random.seed(0)
pd.set_option("display.max_columns", None)
from sklearn.neighbors import LocalOutlierFactor

# %pip install pyod
# import plotly.express as px


drop_cls = ["*"]
__MODE = "Supervise"
__SEED = 42
__SCALER = "QuantileTransformer"
# X_train, y_train, X_test, y_test, classes_tmp, encoder = preprocess_data(drop_cls, df.copy())


def remove_outliers_lof(X_data, y_data, contamination=0.05, random_seed=None):
    """
    Remove outliers from a dataset using Local Outlier Factor (LOF).

    Parameters:
    - X_data: numpy array, feature matrix
    - y_data: numpy array, label array
    - contamination: float, the proportion of outliers in the dataset
    - random_seed: int or None, seed for reproducibility

    Returns:
    - X_no_outliers: numpy array, feature matrix without outliers
    - y_no_outliers: numpy array, label array without outliers
    """

    unique_classes = np.unique(y_data)

    X_no_outliers = np.empty((0, X_data.shape[1]), dtype=X_data.dtype)
    y_no_outliers = np.empty(0, dtype=y_data.dtype)

    for label in unique_classes:
        # Select samples belonging to the current class
        # print(label)
        class_mask = y_data == label
        X_class = X_data[class_mask]
        if label == 0:
            X_no_outliers = np.vstack((X_no_outliers, X_class))
            y_no_outliers = np.concatenate((y_no_outliers, y_data[class_mask]))
        else:
            # Apply LOF to detect outliers
            lof = LocalOutlierFactor(contamination=contamination)
            outliers_mask = lof.fit_predict(X_class) == -1

            # Remove outliers from the current class
            X_no_outliers = np.vstack((X_no_outliers, X_class[~outliers_mask]))
            y_no_outliers = np.concatenate(
                (y_no_outliers, y_data[class_mask][~outliers_mask])
            )

    return X_no_outliers, y_no_outliers


def prepare_data(data, target, cls_drop):
    classes = np.unique(target)
    if __MODE == "Novelty_multi":
        mask = ~np.isin(classes, cls_drop)
        known = classes[mask]
    elif __MODE == "1_Cls":
        known = "0_normal"
    else:
        known = classes

    data_train, data_test, target_train, target_test = train_test_split(
        data, target, test_size=0.3, stratify=target, random_state=__SEED
    )

    # Loại bỏ các class không biết trong tập train
    mask = np.array([y in known for y in target_train])

    X_train = data_train[mask]
    y_train = target_train[mask]

    idx = y_train.argsort()
    X_train = X_train[idx]
    y_train = y_train[idx]

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(y_train)
    X_test = data_test
    y_labels = target_test

    if __MODE == "Novelty_multi":
        # Test labels are 1 if novel, otherwise 0.
        # y_test_bina = np.array([1 if cl not in known else 0 for cl in y_labels])
        y_test = np.array(
            [-1 if cl not in known else encoder.transform([cl])[0] for cl in y_labels]
        )
        # y_test = np.array([cl+"-1" if cl not in known else cl for cl in y_labels])

    if __MODE == "Supervise":
        # y_test_bina = np.array([1 if cl != 0 else 0 for cl in y_labels])

        y_test = encoder.transform(y_labels)

    if __MODE == "1_Cls":
        y_test = np.array(
            [1 if cl not in known else encoder.transform([cl])[0] for cl in y_labels]
        )

    # encoder = LabelEncoder()
    # y_test = encoder.fit_transform(y_test)
    # y_train = encoder.transform(y_train)
    classes = np.unique(y_train)

    return X_train, y_train, X_test, y_test, classes, encoder


def Get_Scaler(name):
    # (StandardScaler, MinMaxScaler, RobustScaler, Normalizer)
    if name == "StandardScaler":
        return StandardScaler()
    if name == "MinMaxScaler":
        return MinMaxScaler()
    if name == "RobustScaler":
        return RobustScaler()
    if name == "Normalizer":
        return Normalizer()
    if name == "QuantileTransformer":
        return QuantileTransformer(output_distribution="normal", random_state=__SEED)
    return None


def preprocess_data(drop_cls, data):
    datasets = data.to_numpy()
    labels = datasets[:, -1]
    dataset = datasets[:, :-1]

    ## ========================== Running Main Model ================================================

    X_train, y_train, X_test, y_test, classes_tmp, encoder = prepare_data(
        dataset, labels, drop_cls
    )

    # print(f"X_train shape: {X_train.shape}")
    # print(f"y_train counts: {np.unique(y_train, return_counts=True)}")

    # X_train, y_train = reduce_trainning_data(X_train, y_train)

    ## ========================== Scaler data ================================================
    scaler = Get_Scaler(name=__SCALER)
    scaler.fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)

    # Remove outliers
    X_train, y_train = remove_outliers_lof(X_train, y_train)

    print(f"X_train shape: {X_train.shape}")
    print(f"y_train counts: {np.unique(y_train, return_counts=True)}")

    print(f"X_test shape: {X_test.shape}")
    print(f"y_test counts: {np.unique(y_test, return_counts=True)}")

    return X_train, y_train, X_test, y_test, classes_tmp, encoder


from sklearn.metrics.pairwise import pairwise_kernels


def K(X, Y=None, metric="poly", coef0=1, gamma=None, degree=3):
    if metric == "poly":
        k = pairwise_kernels(
            X, Y=Y, metric=metric, coef0=coef0, gamma=gamma, degree=degree
        )
    elif metric == "linear":
        k = pairwise_kernels(X, Y=Y, metric=metric)
    elif metric == "sigmoid":
        k = pairwise_kernels(X, Y=Y, metric=metric, coef0=coef0, gamma=gamma)
    elif metric == "rbf":
        k = pairwise_kernels(X, Y=Y, metric=metric, gamma=gamma)
    return k


def kernel_distance_matrix(matrix1=None, matrix2=None, kernel=None, gamma=None):
    """
    Calculate the distance between two matrices using the kernel trick.
    Parameters:
    - matrix1: The first input matrix (NumPy array).
    - matrix2: The second input matrix (NumPy array).
    - gamma: The gamma parameter for the RBF kernel.
    Returns:
    - distance_matrix: The distance matrix between the two input matrices.
    """

    if matrix1.shape[1] != matrix2.shape[1]:
        raise ValueError(
            "The number of features in the input matrices must be the same."
        )
    Kaa = []
    for i in range(len(matrix1)):
        Kaa.append(K(matrix1[i, :].reshape(1, -1), metric=kernel))
    Kaa = np.asarray(Kaa).ravel().reshape(len(Kaa), 1)
    Kab = K(matrix1, matrix2, metric=kernel)
    Kbb = []
    for i in range(len(matrix2)):
        Kbb.append(K(matrix2[i, :].reshape(1, -1), metric=kernel))
    Kbb = np.asarray(Kbb).ravel()
    d = Kaa - 2 * Kab + Kbb  # shape: (matrix1,matrix2)
    return d


def calculate_accuracy_for_label(y_true, y_predict, label):
    """
    Calculate accuracy for a specific label.

    Parameters:
    - y_true: The true labels (1D NumPy array).
    - y_predict: The predicted labels (1D NumPy array).
    - label: The specific label for which to calculate accuracy.

    Returns:
    - accuracy: The accuracy for the specified label.
    """
    # Create a boolean mask for the specified label
    mask = y_true == label

    # Extract true labels and predicted labels for the specified label
    true_labels_for_label = y_true[mask]
    predicted_labels_for_label = y_predict[mask]

    # Calculate accuracy for the specified label
    accuracy = np.mean(true_labels_for_label == predicted_labels_for_label)
    # print(accuracy)
    return accuracy


class kINN:
    def __init__(self, R=1, kernel="linear", mode="Supervise"):
        self.R = R
        self.kernel = kernel
        self.distance_matrix = None
        self.cluster_labels = None
        self.cluster_map = None
        self.N = None
        # self.n_clusters = n_clusters
        self.X = None
        self.M = None
        self.is_fit = False
        self.DNN_test = None
        self.distance_matrix_test = None
        self.mode = mode

    def _Bruteforce_threshold(self, y_test, y_pred, scores):
        # d = Decimal(np.min(scores))
        # min_th = max(1e-8,pow(10, d.as_tuple().exponent))
        # d = Decimal(np.max(scores))
        # max_th = min(1e-2,pow(10, d.as_tuple().exponent))

        # print("======================= DEBUG =======================")
        # print(min_th, max_th)
        # print("======================= DEBUG =======================")
        min_th = 1e-7
        max_th = 1e-1
        # __step = int(max_th / min_th)
        __step = 10000
        mcc = matthews_corrcoef(y_test, y_pred)
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))

        for id in __rag[1:]:
            # print("DEBUG:", id)
            for x in np.linspace(min_th, max_th, num=__step):
                y_pred_adv_tmp = np.array(
                    [
                        -1 if (y_p == id) and (sc > x) else y_p
                        for y_p, sc in zip(y_pred, scores)
                    ]
                )
                mcc_tmp = matthews_corrcoef(y_test, y_pred_adv_tmp)
                ndr_tmp = calculate_accuracy_for_label(y_test, y_pred_adv_tmp, -1)
                if np.mean([mcc_tmp * 2, ndr_tmp]) > np.mean([mcc * 2, ndr]):
                    y_pred_adv = y_pred_adv_tmp
                    mcc = mcc_tmp
                    ndr = ndr_tmp
                    thr[id] = x
            y_pred = y_pred_adv
        print("DEBUG - update mcc:", mcc, ndr, thr)
        return y_pred_adv, mcc, thr

    def _Bruteforce_threshold_1_cls(self, y_test, y_pred, scores):
        # d = Decimal(np.min(scores))
        # min_th = max(1e-8,pow(10, d.as_tuple().exponent))
        # d = Decimal(np.max(scores))
        # max_th = min(1e-2,pow(10, d.as_tuple().exponent))

        # print("======================= DEBUG =======================")
        # print(min_th, max_th)
        # print("======================= DEBUG =======================")
        min_th = 1e-7
        max_th = 1e-1
        # __step = int(max_th / min_th)
        __step = 10000
        mcc = matthews_corrcoef(y_test, y_pred)
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))

        # for id in __rag[0]:
        id = 0
        for x in np.linspace(min_th, max_th, num=__step):
            y_pred_adv_tmp = np.array(
                [
                    1 if (y_p == id) and (sc > x) else y_p
                    for y_p, sc in zip(y_pred, scores)
                ]
            )
            mcc_tmp = matthews_corrcoef(y_test, y_pred_adv_tmp)
            ndr_tmp = calculate_accuracy_for_label(y_test, y_pred_adv_tmp, 1)
            if np.mean([mcc_tmp * 2, ndr_tmp]) > np.mean([mcc * 2, ndr]):
                y_pred_adv = y_pred_adv_tmp
                mcc = mcc_tmp
                ndr = ndr_tmp
                thr[id] = x
        y_pred = y_pred_adv

        print("DEBUG - update mcc:", mcc, ndr, thr)
        return y_pred_adv, mcc, thr

    def fit(self, X, y=None, single=False, type="distance"):
        """
        Fit the kINN model to the input data.

        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.
        - y: Input label, a array where each row represents a label for corresponding label
        - type: the strategy to calculate distance, support:
                                                            + "distance" - use only distance
                                                            + "density" - use LOF score as weight when calculate distance
        """
        self.X = X
        if (y is None) and (self.mode == "1_Cls"):
            # -np.ones(self.N, dtype=int)
            y = np.zeros(X.shape[0], dtype=int)
        self._fit_classify(X, y, type)
        self.is_fit = True
        if single == True:
            X_new = self.__map_to_single_point(X)

            return X_new, self.cluster_labels, self.cluster_map
        else:
            return self.cluster_labels, self.cluster_map

    def _calculate_lof(self, dis_mat, k_dis, d_nn, N_cnt):
        # calculate reachability distance

        re_dis_k = np.array(
            [[max(dis_mat[i, k], k_dis[k]) for k in range(N_cnt)] for i in range(N_cnt)]
        )

        # calculate Local Reachability Density (LRD)

        lrd = np.array([1.0 / np.mean(re_dis_k[x, d_nn[x]]) for x in range(N_cnt)])

        # calculate LOF
        lof = np.array([np.mean(lrd[d_nn[x]]) / lrd[x] for x in range(N_cnt)])

        return lof

    def _fit_classify(self, X, y, type="distance"):
        N = X.shape[0]

        D_NN = np.empty((N,), dtype=object)
        INNR = np.empty((N,), dtype=object)

        classes, cls_cnt = np.unique(y, return_counts=True)

        for cls, N_cnt in zip(classes, cls_cnt):
            indicates = np.asarray(y == cls).nonzero()[0]
            X_cls = X[indicates]
            y_cls = y[indicates]

            dis_mat = kernel_distance_matrix(
                matrix1=X_cls, matrix2=X_cls, kernel=self.kernel
            )

            if type == "density":
                k_dis = -np.ones(N_cnt, dtype=float)
                d_nn = np.empty((N_cnt,), dtype=object)
                re_dis_k = -np.ones((N_cnt, N_cnt), dtype=float)

                for i in range(N_cnt):
                    dis_mat[i, i] = 0
                    tmp = dis_mat[i, :].argsort()

                    # Some case that 2 point are too close
                    dnn_tmp = [i]
                    cnt = 0
                    for x in tmp:
                        if abs(dis_mat[i, dnn_tmp[-1]] - dis_mat[i, x]) > 1e-9:
                            dnn_tmp.append(x)
                            cnt += 1
                            k_dis[i] = dis_mat[i, x]
                        else:
                            dnn_tmp.append(x)

                        if cnt >= self.R:
                            break
                    d_nn[i] = np.array(dnn_tmp[1:])

                lof = self._calculate_lof(dis_mat, k_dis, d_nn, N_cnt)

                # Update new matrix
                dis_mat = np.array(
                    [
                        [dis_mat[i, k] * lof[k] for k in range(N_cnt)]
                        for i in range(N_cnt)
                    ]
                )

            # calculate D_N
            for i in range(N_cnt):
                dis_mat[i, i] = 0
                tmp = dis_mat[i, :].argsort()

                id = indicates[i]
                D_NN[id] = np.array(indicates[tmp])

                # Some case that 2 point are too close
                dnn_tmp = [i]
                cnt = 0
                for x in tmp:
                    if abs(dis_mat[i, dnn_tmp[-1]] - dis_mat[i, x]) > 1e-9:
                        dnn_tmp.append(x)
                        cnt += 1
                    else:
                        dnn_tmp.append(x)

                    if cnt >= self.R:
                        break

                D_NN[id] = np.array(indicates[dnn_tmp[1:]])

            self.D_NN = D_NN

            for i in tqdm(indicates, desc=f"Processing class {cls}"):
                NN = D_NN[i]
                tmp = []
                for p in NN:
                    p_near_neighbor = D_NN[p]
                    if i in p_near_neighbor:
                        tmp.append(p)

                pair = (i, tmp)
                INNR[i] = pair

        self.INNR = INNR
        self.N = N
        self.cluster_labels, self.no_cluser = self._label_clusters()

        cluster_map = np.full(self.no_cluser, -1)

        for x_tmp, y_tmp in zip(self.cluster_labels, y):
            if cluster_map[x_tmp] == -1:
                cluster_map[x_tmp] = y_tmp
            else:
                if cluster_map[x_tmp] != y_tmp:
                    print("Debug - Loi KNN")

        self.cluster_map = cluster_map

    # def _fit_cluster(self,X):
    #     N = X.shape[0]
    #     dis_mat = kernel_distance_matrix(matrix1 = X, matrix2 = X, kernel = self.kernel)
    #     D_NN = []
    #     for i in range(N):
    #         dis_mat[i,i] = 0
    #         tmp = dis_mat[i,].argsort()
    #         D_NN.append(tmp)

    #     D_NN = np.array(D_NN)
    #     self.D_NN = D_NN
    #     INNR = []

    #     for i in range(N):
    #         NN = D_NN[i, 1:self.R+1]

    #     tmp = []
    #     for p in NN:
    #         p_near_neighbor = D_NN[p, 1:self.R+1]
    #         if i in p_near_neighbor:
    #             tmp.append(p)

    #     pair = (i, tmp)
    #     INNR.append(pair)
    # self.INNR = INNR

    # self.N = N
    # self.cluster_labels, self.no_cluser = self._label_clusters()

    def _label_clusters(self):
        """
        Label clusters using deep find search (DFS) algorithm.

        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.

        Returns:
        - labels: A numpy array containing cluster labels for each sample.

        """
        # print(self.INN)
        labels = -np.ones(self.N, dtype=int)
        current_label = 0

        # INNR = sorted(self.INNR,key=lambda x: len(x[1]), reverse=True)
        for x in self.INNR:
            id = x[0]
            if labels[id] == -1:
                queue = [id]
                labels[id] = current_label
                # _debug = 0
                for q in queue:
                    neighbors = self.INNR[q][1]
                    for neighbor in neighbors:
                        if labels[neighbor] == -1:
                            queue.append(neighbor)
                            labels[neighbor] = current_label
                current_label += 1
        return labels, current_label

    def _dfs_label_clusters(self, i, current_label, labels):
        """
        DFS algorithm to label clusters.

        Parameters:
        - X: Input data, a 2D numpy array where each row represents a sample.
        - i: Index of the current sample being explored.
        - current_label: Current cluster label.
        - labels: A numpy array containing cluster labels for each sample.

        """
        if labels[i] != -1:
            return

        labels[i] = current_label

        neighbors = self.INNR[i][1]
        for neighbor in neighbors:
            #
            self._dfs_label_clusters(neighbor, current_label, labels)

    def __map_to_single_point(self, X):

        a = self.cluster_labels
        x_new = []
        a_new = []
        for cl in np.unique(a):
            mask = np.isin(a, cl)
            known = X[mask]
            a_new.append(self.cluster_map[cl])
        # print(x_new)
        # print(a_new)
        self.cluster_labels = np.array(a_new)

        return np.array(x_new)

    def find_nearest_neighbors(self, X, x_i):
        """
        Find the R nearest neighbors of x_i using kernel trick.

        Parameters:
        - x_i: The input sample.

        Returns:
        - neighbors: A set of R nearest neighbors for x_i.

        """
        if self.distance_matrix is None:
            raise ValueError("Model not fitted. Call fit() first.")

        # Calculate kernel vector
        kernel_vector = self.distance_matrix[x_i].flatten()

        # Get indices of R nearest neighbors
        nearest_indices = np.argsort(kernel_vector)[1 : self.R + 1]

        return set(nearest_indices)

    def predict(self, X_test, y=None):
        """
        Predict the cluster labels for the input samples.

        Parameters:
        - X_test: Input data, a 2D numpy array where each row represents a sample.

        Returns:
        - predicted_labels: A numpy array containing predicted cluster labels for each sample.

        """
        if self.is_fit == False:
            raise ValueError("Model not fitted. Call fit() first.")

        N_test = X_test.shape[0]
        self.M = N_test
        dis_mat_X_test = kernel_distance_matrix(
            matrix1=X_test, matrix2=self.X, kernel=self.kernel
        )
        self.distance_matrix_test = dis_mat_X_test
        D_NN_test = []
        # print("Khoảng cách X_test -> X_train:\n ",dis_mat_X_test,"\n")
        for i in range(N_test):
            # dis_mat_X_test[i,i] = 0
            tmp = dis_mat_X_test[i,].argsort()
            D_NN_test.append(tmp)

        D_NN_test = np.array(D_NN_test)
        # print(D_NN_test.shape)
        self.D_NN_test = D_NN_test
        INNR_X_test = []
        # Tìm INNR_X_test
        for i in range(N_test):
            NN = D_NN_test[i, 1 : self.R + 1]
            # print(NN)
            tmp = []
            for p in NN:
                p_near_neighbor = D_NN_test.T[p, 1 : self.R + 1]
                # print("neighbor: ",p_near_neighbor)
                if i in p_near_neighbor:
                    # print(p_near_neighbor)
                    tmp.append(p)
            pair = (i, tmp)
            # print(pair)
            INNR_X_test.append(pair)
        self.INNR_test = INNR_X_test

        if self.mode == "Supervise":
            labels = self._predict_multi()
            return labels
        elif self.mode == "Novelty_multi":
            labels, mcc, threshold = self._predict_novelty(y)
            return labels, mcc, threshold
        else:
            labels, mcc, threshold = self._predict_1Class(y)
            return labels, mcc, threshold

    def _predict_multi(self):
        labels = -np.ones(self.M, dtype=int)
        # c = 0
        for pair in self.INNR_test:
            idx = pair[0]
            if pair[1] != []:  # Kiểm tra xem danh sách neighbor có rỗng không
                neighbors = pair[1]
                # print(id, "neigibor = ",neighbors)
                labels[idx] = self.cluster_map[self.cluster_labels[neighbors[0]]]
                # c+= 1
                # print(self.cluster_labels[neighbors[0]])
            else:
                labels[idx] = self.cluster_map[
                    self.cluster_labels[self.D_NN_test[idx][0]]
                ]
        # print("Count: ",c)
        return labels

    def _predict_novelty(self, y):
        scores_mat = self.distance_matrix_test
        y_pred = [self.cluster_labels[x] for x in np.argmin(scores_mat, axis=1)]

        for i in range(self.M):
            y_pred[i] = self.cluster_map[y_pred[i]]

        scores = np.amin(scores_mat, axis=1)
        y_pred_adv, mcc, threshold = self._Bruteforce_threshold(y, y_pred, scores)

        print(f"MCC: {mcc}", f"threshold: {threshold}")

        return y_pred_adv, mcc, threshold

    def _predict_1Class(self, y):

        scores_mat = self.distance_matrix_test
        # print(scores_mat)
        # y_pred = [self.cluster_labels[x] for x in np.argmin(scores_mat, axis=1)]

        # for i in range(self.M):
        #     y_pred[i] = self.cluster_map[y_pred[i]]
        y_pred = np.zeros(self.M, dtype=int)
        scores = np.amin(scores_mat, axis=1)
        y_pred_adv, mcc, threshold = self._Bruteforce_threshold_1_cls(y, y_pred, scores)
        # print("DEBUG- y_pred: ", y_pred)

        print(f"MCC: {mcc}", f"threshold: {threshold}")

        return y_pred_adv, mcc, threshold


import pickle

# Load model và các thành phần từ file
with open("kinn_model.pkl", "rb") as f:
    saved_data = pickle.load(f)

# Truy xuất các thành phần
kinn_model_loaded = saved_data["model"]
cluster_train = saved_data["cluster_train"]
cluster_map = saved_data["cluster_map"]
parameters = saved_data["parameters"]

# In thông tin đã tải
print("Model đã được tải thành công!")
print("Thông số đã lưu:", parameters)


import joblib

# Load the saved scaler from the 'scaler.pkl' file
scaler = joblib.load("scaler.pkl")


from scapy.all import sniff
from Feature_extraction import Feature_extraction

# Tạo một instance của lớp Feature_extraction
feature_extractor = Feature_extraction()


# Hàm callback để xử lý mỗi gói tin được capture
def process_packet(packet):
    raw_packet = bytes(packet)
    features = feature_extractor.pcap_evaluation(raw_packet)
    # print("features:", features)
    # for feature in features:
    #     print(f"{feature}: {type(feature)}")
    features = np.array(features).reshape(1, -1)
    features_tranform = scaler.transform(features)
    # print("features_tranform:", features_tranform)
    y_pred = kinn_model_loaded.predict(features_tranform)
    print("y_pred:", y_pred)


# Capture các gói tin mạng realtime trên card NIC cụ thể
sniff(prn=process_packet, count=10, iface="Wi-Fi")
