//! Borrowed generic block symbols for one selected enclosing wire encoder.
use super::*;

impl BlockEncoder {
    /// Offer a systematic vector without serializing a private wire envelope.
    pub fn systematic_with<T>(
        &mut self,
        source: SourceId,
        encode: impl FnOnce(SymbolView<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        let index = usize::from(source.0);
        if index >= self.count {
            return Err(Error::InvalidDimensions);
        }
        if self.usage.is_none() && self.coefficients.len() < self.count {
            self.coefficients.resize(self.count, 0);
        }
        self.coefficients[..self.count].fill(0);
        self.coefficients[index] = 1;
        encode(SymbolView {
            generation: self.generation,
            symbol: SymbolId(u32::from(source.0)),
            kind: SymbolKind::Systematic,
            source_count: self.count,
            coded_bytes: self.width,
            coefficients: &self.coefficients[..self.count],
            payload: &self.sources[index],
        })
    }

    /// Offer the maintained Cauchy equation; only successful encoding consumes its ID.
    pub fn cauchy_repair_with<T>(
        &mut self,
        repair_index: u16,
        encode: impl FnOnce(SymbolView<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        field::cauchy_column(self.count as u16, repair_index)?;
        self.config.work(self.count, self.width)?;
        let symbol = self.next_repair.ok_or(Error::SymbolExhausted)?;
        if self.usage.is_none() {
            self.coefficients.resize(self.count, 0);
            self.repair_payload.resize(self.width, 0);
        }
        field::cauchy_into(
            self.count as u16,
            repair_index,
            &mut self.coefficients[..self.count],
        )?;
        repair_payload(
            &self.coefficients[..self.count],
            &self.sources[..self.count],
            &mut self.repair_payload[..self.width],
        );
        let value = encode(SymbolView {
            generation: self.generation,
            symbol,
            kind: SymbolKind::Repair,
            source_count: self.count,
            coded_bytes: self.width,
            coefficients: &self.coefficients[..self.count],
            payload: &self.repair_payload[..self.width],
        })?;
        self.next_repair = symbol.0.checked_add(1).map(SymbolId);
        Ok(value)
    }
}
