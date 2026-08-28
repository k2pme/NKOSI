fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .file_descriptor_set_path("proto/central_descriptor.bin")
        .compile(&["proto/central.proto"], &["proto"])?;
    Ok(())
}
