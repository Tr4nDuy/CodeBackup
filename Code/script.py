import sys
import traceback
sys.path.append('.')

try:
    print('Testing imports...')
    import pickle
    print('✓ pickle imported')
    
    from program_siem import kINN
    print('✓ kINN imported from program_siem')
    
    # Test loading the original model
    print('Testing model loading...')
    model_path = '../Saved model/kinn_model.pkl'
    
    # Create new kINN instance
    new_model = kINN()
    print('✓ kINN instance created')
    
    # Load using the compatible method
    new_model.load_model_compatible(model_path)
    print('✓ Model loaded successfully!')
    
    # Check key attributes
    print('Model attributes:')
    print(f'  - R (k): {getattr(new_model, "R", "Not found")}')
    print(f'  - kernel: {getattr(new_model, "kernel", "Not found")}')
    print(f'  - is_fit: {getattr(new_model, "is_fit", "Not found")}')
    
    if hasattr(new_model, "X") and new_model.X is not None:
        print(f'  - X shape: {new_model.X.shape}')
    else:
        print('  - X shape: Not found')
        
    cluster_labels_found = hasattr(new_model, "cluster_labels") and new_model.cluster_labels is not None
    cluster_map_found = hasattr(new_model, "cluster_map") and new_model.cluster_map is not None
    
    print(f'  - cluster_labels: {"Found" if cluster_labels_found else "Not found"}')
    print(f'  - cluster_map: {"Found" if cluster_map_found else "Not found"}')

except Exception as e:
    print(f'✗ Error: {e}')
    print('Full traceback:')
    traceback.print_exc()