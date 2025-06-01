import pickle
import sys
import traceback
sys.path.append('.')

# Import the original kINN class so pickle can find it
from program import kINN

try:
    # Load and inspect the original model
    model_path = '../Saved model/kinn_model.pkl'

    print("=== Inspecting Original Model ===")
    with open(model_path, 'rb') as f:
        original_model = pickle.load(f)

    print(f"Model type: {type(original_model)}")
    
    if isinstance(original_model, dict):
        print(f"\nKeys: {list(original_model.keys())}")
        
        # Examine the actual model object
        if 'model' in original_model:
            kinn_model = original_model['model']
            print(f"\n=== kINN Model Object ===")
            print(f"Model type: {type(kinn_model)}")
            
            # Check key attributes
            key_attrs = ['R', 'kernel', 'is_fit', 'X', 'cluster_labels', 'cluster_map', 'mode']
            for attr in key_attrs:
                if hasattr(kinn_model, attr):
                    value = getattr(kinn_model, attr)
                    if hasattr(value, 'shape'):
                        print(f"  ✓ {attr}: {type(value).__name__} shape={value.shape}")
                    elif isinstance(value, (list, tuple)):
                        print(f"  ✓ {attr}: {type(value).__name__} len={len(value)}")
                    elif isinstance(value, dict):
                        print(f"  ✓ {attr}: dict with {len(value)} keys")
                    else:
                        print(f"  ✓ {attr}: {value}")
                else:
                    print(f"  ✗ {attr}: Not found")
        
        # Check external data
        if 'cluster_train' in original_model:
            cluster_train = original_model['cluster_train']
            print(f"\n=== External Data ===")
            print(f"  cluster_train: shape={cluster_train.shape}")
        
        if 'cluster_map' in original_model:
            cluster_map = original_model['cluster_map']
            print(f"  cluster_map: shape={cluster_map.shape}")
        
        if 'parameters' in original_model:
            params = original_model['parameters']
            print(f"  parameters: {params}")

except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc()
