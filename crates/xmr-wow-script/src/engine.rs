use crate::backend::Backend;
pub struct Engine<B: Backend>(std::marker::PhantomData<B>);
