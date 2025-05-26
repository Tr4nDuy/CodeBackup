import pandas as pd
import numpy as np
import os
import pickle
import joblib
import time
import logging
import argparse
from sklearn.metrics import matthews_corrcoef
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics.pairwise import pairwise_kernels
from tqdm import tqdm
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Set global configurations
np.random.seed(42)
pd.set_option("display.max_columns", None)

__MODE = "Supervise"
__SEED = 42
__SCALER = "QuantileTransformer"

def K(X, Y=None, metric="poly", coef0=1, gamma=None, degree=3):
    """Compute kernel matrix between X and Y."""
    params = {}
    if metric == "poly":
        params = {"coef0": coef0, "gamma": gamma, "degree": degree}
    elif metric == "sigmoid":
        params = {"coef0": coef0, "gamma": gamma}
    elif metric == "rbf":
        params = {"gamma": gamma}
    
    return pairwise_kernels(X, Y=Y, metric=metric, **params)

def kernel_distance_matrix(matrix1, matrix2, kernel="linear", gamma=None):
    """
    Calculate distance matrix between two matrices using specified kernel.
    """
    if matrix1.shape[1] != matrix2.shape[1]:
        raise ValueError("The number of features in the input matrices must be the same.")
    
    # Calculate diagonal elements of kernel matrices (K(x_i, x_i) for all i)
    Kaa = np.array([K(x.reshape(1, -1), metric=kernel) for x in matrix1]).flatten()
    Kbb = np.array([K(x.reshape(1, -1), metric=kernel) for x in matrix2]).flatten()
    
    # Calculate cross terms K(x_i, y_j) for all i,j
    Kab = K(matrix1, matrix2, metric=kernel)
    
    # Compute kernel distance: K(x,x) - 2*K(x,y) + K(y,y)
    # Broadcasting to compute distances between all pairs
    d = Kaa.reshape(-1, 1) - 2 * Kab + Kbb
    
    return d

def calculate_accuracy_for_label(y_true, y_predict, label):
    """
    Calculate accuracy for a specific label.
    
    Parameters:
    - y_true: True labels
    - y_predict: Predicted labels
    - label: Target label
    
    Returns:
    - Accuracy for the specified label
    """
    mask = y_true == label
    if not np.any(mask):
        return 0.0
    
    return np.mean(y_true[mask] == y_predict[mask])


class kINN:
    def __init__(self, R=1, kernel="linear", mode="Supervise"):
        self.R = R
        self.kernel = kernel
        self.distance_matrix = None
        self.cluster_labels = None
        self.cluster_map = None
        self.N = None
        self.X = None
        self.M = None
        self.is_fit = False
        self.DNN_test = None
        self.distance_matrix_test = None
        self.mode = mode
        self.D_NN = None

    def _Bruteforce_threshold(self, y_test, y_pred, scores):
        min_th = 1e-7
        max_th = 1e-1
        __step = 10000
        mcc = matthews_corrcoef(y_test, y_pred)
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))

        for id in __rag[1:]:
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
        min_th = 1e-7
        max_th = 1e-1
        __step = 10000
        mcc = matthews_corrcoef(y_test, y_pred)
        mcc = 0
        ndr = 0
        y_pred_adv = y_pred

        __rag = np.unique(y_test)
        thr = -np.ones(len(__rag))
        
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
        labels = -np.ones(self.N, dtype=int)
        current_label = 0
        
        for x in self.INNR:
            id = x[0]
            if labels[id] == -1:
                queue = [id]
                labels[id] = current_label
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
            self._dfs_label_clusters(neighbor, current_label, labels)
            
    def __map_to_single_point(self, X):
        a = self.cluster_labels
        x_new = []
        a_new = []
        for cl in np.unique(a):
            mask = np.isin(a, cl)
            known = X[mask]
            a_new.append(self.cluster_map[cl])
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
        nearest_indices = np.argsort(kernel_vector)[1:self.R+1]
        
        return set(nearest_indices)
        
    def predict(self, X_test, y=None):
        """
        Predict the cluster labels for the input samples.
        
        Parameters:
        - X_test: Input data, a 2D numpy array where each row represents a sample.
        
        Returns:
        - predicted_labels: A numpy array containing predicted cluster labels for each sample.
        """
        if not self.is_fit:
            raise ValueError("Model not fitted. Call fit() first.")
            
        N_test = X_test.shape[0]
        self.M = N_test
        dis_mat_X_test = kernel_distance_matrix(
            matrix1=X_test, matrix2=self.X, kernel=self.kernel
        )
        self.distance_matrix_test = dis_mat_X_test
        D_NN_test = []
        
        for i in range(N_test):
            tmp = dis_mat_X_test[i,].argsort()
            D_NN_test.append(tmp)
            
        D_NN_test = np.array(D_NN_test)
        self.D_NN_test = D_NN_test
        INNR_X_test = []
        
        for i in range(N_test):
            NN = D_NN_test[i, 1:self.R+1]
            tmp = []
            for p in NN:
                # Kiểm tra p có hợp lệ và D_NN có tồn tại không
                if (hasattr(self, 'D_NN') and self.D_NN is not None and 
                    p < len(self.D_NN) and self.D_NN[p] is not None):
                    p_near_neighbor = self.D_NN[p]
                    if i in p_near_neighbor:
                        tmp.append(p)
            pair = (i, tmp)
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
        for pair in self.INNR_test:
            idx = pair[0]
            if pair[1]:  # Kiểm tra xem danh sách neighbor có rỗng không
                neighbors = pair[1]
                labels[idx] = self.cluster_map[self.cluster_labels[neighbors[0]]]
            else:
                labels[idx] = self.cluster_map[
                    self.cluster_labels[self.D_NN_test[idx][0]]
                ]
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
        y_pred = np.zeros(self.M, dtype=int)
        scores = np.amin(scores_mat, axis=1)
        y_pred_adv, mcc, threshold = self._Bruteforce_threshold_1_cls(y, y_pred, scores)
        
        print(f"MCC: {mcc}", f"threshold: {threshold}")
        return y_pred_adv, mcc, threshold


def main():
    try:
        # Tạo parser để đọc argument từ command line
        parser = argparse.ArgumentParser(description="Read CSV file from argument")
        parser.add_argument("csv_file", type=str, help="Path to CSV file")

        # Lấy argument từ command line
        args = parser.parse_args()
        csv_file_path = args.csv_file
        
        # Kiểm tra file CSV tồn tại
        if not os.path.isfile(csv_file_path):
            raise FileNotFoundError(f"File CSV không tồn tại: {csv_file_path}")
        
        # Load model và các thành phần từ file
        model_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "kinn_model.pkl")
        if not os.path.isfile(model_path):
            raise FileNotFoundError(f"File model không tồn tại: {model_path}")
            
        try:
            with open(model_path, "rb") as f:
                saved_data = pickle.load(f)

            # Truy xuất các thành phần
            kinn_model_loaded = saved_data["model"]
            cluster_train = saved_data["cluster_train"]
            cluster_map = saved_data["cluster_map"]
            parameters = saved_data["parameters"]
        except (KeyError, pickle.UnpicklingError) as e:
            raise ValueError(f"File model không hợp lệ: {e}")

        # Đọc dữ liệu
        try:
            df = pd.read_csv(csv_file_path)
            df = df.fillna(0)
        except pd.errors.EmptyDataError:
            raise ValueError("File CSV rỗng")
        except pd.errors.ParserError:
            raise ValueError("Định dạng file CSV không hợp lệ")

        selected_columns = [
            "flow_duration", "flow_byte", "src_port", "dst_port", "Duration", "Rate",
            "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
            "psh_flag_number", "ack_flag_number", "urg_flag_number", "ece_flag_number",
            "cwr_flag_number", "ack_count", "syn_count", "fin_count", "urg_count",
            "rst_count", "CoAP", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
            "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min",
            "Max", "AVG", "Std", "Tot size", "IAT", "Magnitue", "Radius", "Covariance",
            "Variance", "Weight", "DS status", "Fragments", "Sequence number",
            "flow_idle_time", "flow_active_time"
        ]
        log_columns = [
            "src_ip", "dst_ip"
        ]
        
        # Kiểm tra các cột cần thiết tồn tại trong DataFrame
        missing_cols = [col for col in selected_columns if col not in df.columns]
        if missing_cols:
            raise ValueError(f"File CSV thiếu các cột: {', '.join(missing_cols)}")
            
        missing_log_cols = [col for col in log_columns if col not in df.columns]
        if missing_log_cols:
            raise ValueError(f"File CSV thiếu các cột log: {', '.join(missing_log_cols)}")
        
        # Tạo DataFrame mới chỉ chứa các cột đã chọn
        df_new = df[selected_columns]
        df_log = df[log_columns]
        df_new.insert(0, "", range(1, len(df_new) + 1))

        # Load the saved scaler from the 'scaler.pkl' file
        scaler_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "scaler.pkl")
        if not os.path.isfile(scaler_path):
            raise FileNotFoundError(f"File scaler không tồn tại: {scaler_path}")
            
        try:
            scaler = joblib.load(scaler_path)
        except Exception as e:
            raise ValueError(f"Không thể load file scaler: {e}")

        # Chuẩn hóa dữ liệu
        try:
            X_transformed = scaler.transform(df_new.values)
        except Exception as e:
            raise ValueError(f"Lỗi khi chuẩn hóa dữ liệu: {e}")

        # Dự đoán với mô hình
        try:
            y_pred = kinn_model_loaded.predict(X_transformed)
            print(f"Đã dự đoán xong {len(y_pred)} gói tin")
        except Exception as e:
            raise ValueError(f"Lỗi khi dự đoán: {e}")

        encoder_path = os.path.join(os.path.dirname(__file__), "..", "Saved model", "label_encoder.pkl")
        if not os.path.isfile(encoder_path):
            raise FileNotFoundError(f"File encoder không tồn tại: {encoder_path}")
            
        try:
            encoder = joblib.load(encoder_path)  # Load encoder đã lưu
            y_pred_labels = encoder.inverse_transform(y_pred)
        except Exception as e:
            raise ValueError(f"Không thể load file encoder hoặc chuyển đổi nhãn: {e}")

        # Tạo thư mục logs nếu chưa tồn tại
        logs_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        log_file_path = os.path.join(logs_dir, "event_log.log")
        
        # Thiết lập cấu hình cho logger
        logging.basicConfig(
            filename=log_file_path,  # Tên file log
            level=logging.INFO,        # Mức độ ghi log (INFO, DEBUG, ERROR, v.v.)
            format='%(asctime)s - %(message)s',  # Định dạng ghi log
            datefmt='%Y-%m-%d %H:%M:%S',  # Định dạng ngày giờ
            force=True  # Ghi đè cấu hình logger nếu đã tồn tại
        )

        # Tạo ánh xạ giữa nhãn và mô tả sự kiện
        log_mapping = {
            "0_normal": "Normal Traffic",
            "TCP": "TCP Scanning Attack",
            "UDP": "UDP Scanning Attack",
            "ICMP": "ICMP Scanning Attack", 
            "ARP": "ARP Scanning Attack"
        }

        # Thông báo bắt đầu xử lý
        print(f"\n{'=' * 50}")
        print(f"Bắt đầu phân tích {len(y_pred)} gói tin...")
        print(f"{'=' * 50}\n")

        # Số lượng từng loại sự kiện
        event_counts = {event_type: 0 for event_type in log_mapping.values()}
        event_counts["Unknown"] = 0

        for i, label in enumerate(y_pred_labels, 1):
            # Lấy thông tin gói tin
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Sử dụng try-except để tránh lỗi nếu index vượt quá
            try:
                src_ip = df_log.iloc[i-1]["src_ip"]
                dst_ip = df_log.iloc[i-1]["dst_ip"]
                src_port = df.iloc[i-1]["src_port"]
                dst_port = df.iloc[i-1]["dst_port"]
            except IndexError:
                src_ip = "N/A"
                dst_ip = "N/A"
                src_port = "N/A"
                dst_port = "N/A"
            
            # Chuyển nhãn thành mô tả sự kiện
            event = log_mapping.get(label, "Unknown event")
            
            # Cập nhật số lượng sự kiện
            if event == "Unknown event":
                event_counts["Unknown"] += 1
            else:
                event_counts[event] += 1
            
            # Format log chuẩn hơn (bỏ dấu phẩy thừa)
            log_message = f"Log {i}: Event='{event}', Src IP='{src_ip}', Src Port='{src_port}', Dst IP='{dst_ip}', Dst Port='{dst_port}', Label='{label}'"
            
            # In log ra console và ghi vào file
            print(f"{timestamp} - {log_message}")
            logging.info(log_message)

        # Hiển thị thống kê
        print(f"\n{'=' * 50}")
        print("Thống kê các sự kiện phát hiện được:")
        for event_type, count in event_counts.items():
            if count > 0:
                print(f"- {event_type}: {count} gói tin")
        print(f"{'=' * 50}")

    except Exception as e:
        error_message = f"Lỗi: {str(e)}"
        print(error_message)
        logging.error(error_message)
        return 1
    
    return 0


if __name__ == "__main__":
    main()
