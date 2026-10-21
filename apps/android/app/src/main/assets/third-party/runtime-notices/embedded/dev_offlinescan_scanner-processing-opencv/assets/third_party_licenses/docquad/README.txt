DocQuadNet-256 offline inference model
Upstream: https://github.com/egdels/makeacopy
Revision: 01bebd394b9dd6f3a692f28aea7c0638085eb4da
Source artifact: app/src/main/assets/docquad/docquadnet256_trained_opset17.ort
Bundled artifact: docquad/docquadnet256.ort (unmodified bytes)
Size: 13404960 bytes
SHA-256: f0f2f52d7d79ff02d346c8f9d0c9e903407366aeea1747cdcff160c401e3e72a

The upstream NOTICE explicitly grants Apache License 2.0 to the independently
created exported ONNX inference model. LICENSE.txt and the full pinned upstream
NOTICE are retained. The model is an ORT-format export of that inference model.
Scope interpretation: the final grant is singular and unqualified rather than
naming DocQuadNet. The DocQuadNet training README identifies its exported ONNX
inference model as the shipped artifact, and the project LICENSE is Apache-2.0.
The preceding Paddle section separately licenses ten different OCR models.
Together these sources support applying the inference grant to this DocQuadNet
artifact. No separate maintainer clarification or legal review was obtained.
The reference preprocessing and heatmap decoder are also Apache-2.0:
Copyright 2026 Christian Kierdorf. This SDK uses a new Kotlin implementation.
No upstream app UI, OCR models, training dataset images or annotations ship here.
Items in UPSTREAM-NOTICE.txt describe the full upstream app, not this SDK's bill
of materials. Only DocQuadNet model and preprocessing/decoding conventions are
used by this implementation.

Training-data provenance caveat: upstream reports training with Doc3D, MIDV-500,
SmartDoc, CORD and DTD. DTD background images lack a clear redistribution grant
and its original website describes research use. No training data is distributed
here; the inference-weight grant is explicit Apache-2.0. This does not establish
individual training-image provenance or remove third-party rights concerns.
See the learned-model evaluation documentation for the reviewed evidence.

Runtime: com.microsoft.onnxruntime:onnxruntime-android:1.24.1, MIT license.
Only CPU inference is enabled. No network access, account, Play services,
downloads or model training are needed to use the bundled model.
