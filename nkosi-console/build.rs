fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../nkosi-central/proto/central.proto")?;
    Ok(())
}
