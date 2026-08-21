#import <React/RCTViewManager.h>

RCT_EXTERN_MODULE(SecureKeypadViewManager, RCTViewManager)
RCT_EXPORT_VIEW_PROPERTY(layout, NSDictionary)
RCT_EXPORT_VIEW_PROPERTY(theme, NSDictionary)
RCT_EXPORT_VIEW_PROPERTY(inputPolicy, NSString)
RCT_EXPORT_VIEW_PROPERTY(maxTokens, NSNumber)
RCT_EXPORT_VIEW_PROPERTY(timeoutMs, NSNumber)
RCT_EXPORT_VIEW_PROPERTY(onMaskedStateChange, RCTBubblingEventBlock)
RCT_EXPORT_VIEW_PROPERTY(onResult, RCTBubblingEventBlock)
