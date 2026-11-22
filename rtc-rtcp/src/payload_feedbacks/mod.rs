/// AFB: application layer feedback that is not REMB.
pub mod application_layer_feedback;
/// FIR: asks a sender for a full intra frame, used when a receiver joins or resyncs.
pub mod full_intra_request;
/// LRR: asks the encoder of a scalable stream for a layer refresh point.
pub mod layer_refresh_request;
/// PLI: tells a sender the receiver lost picture and needs a keyframe.
pub mod picture_loss_indication;
/// REMB: the receiver's estimate of the bitrate the path can carry.
pub mod receiver_estimated_maximum_bitrate;
/// RPSI: names a reference picture in the codec's own terms.
pub mod reference_picture_selection_indication;
/// SLI: reports individual lost slices, for finer-grained repair than PLI.
pub mod slice_loss_indication;
/// TSTR and TSTN: the trade-off between frame rate and picture quality, asked and answered.
pub mod temporal_spatial_tradeoff;
/// VBCM: an H.271 video back channel message.
pub mod video_back_channel_message;
