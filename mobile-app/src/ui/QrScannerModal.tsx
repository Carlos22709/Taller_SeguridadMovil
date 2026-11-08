import { CameraView, useCameraPermissions } from 'expo-camera';
import { useRef } from 'react';
import { Modal, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Button } from './components';
import { colors, radius, space } from './theme';

/** Escáner de QR (otpauth://...) con la cámara. */
export function QrScannerModal({ visible, onClose, onScanned }: { visible: boolean; onClose: () => void; onScanned: (data: string) => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const handled = useRef(false);

  return (
    <Modal visible={visible} animationType="slide" onRequestClose={onClose} onShow={() => {
        handled.current = false;
      }}>
      <SafeAreaView style={styles.container}>
        <Text style={styles.title}>Escanear código QR</Text>
        <Text style={styles.hint}>Apunta al QR de enrolamiento (otpauth://totp/...).</Text>
        <View style={styles.frame}>
          {permission?.granted ? (
            <CameraView
              style={StyleSheet.absoluteFill}
              facing="back"
              barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
              onBarcodeScanned={({ data }) => {
                if (handled.current) return; // el escáner dispara varias veces por segundo
                handled.current = true;
                onScanned(data);
              }}
            />
          ) : (
            <View style={styles.permission}>
              <Text style={styles.permissionText}>
                {permission?.canAskAgain === false
                  ? 'El permiso de cámara fue denegado. Actívalo en Ajustes o pega la semilla manualmente.'
                  : 'Se necesita la cámara para leer el QR.'}
              </Text>
              {permission?.canAskAgain !== false ? <Button label="Permitir cámara" onPress={() => void requestPermission()} /> : null}
            </View>
          )}
        </View>
        <Button label="Cancelar" variant="secondary" onPress={onClose} />
      </SafeAreaView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, padding: space.lg },
  title: { fontSize: 22, fontWeight: '700', color: colors.ink },
  hint: { color: colors.muted, marginTop: space.xs, marginBottom: space.lg },
  frame: { flex: 1, maxHeight: 480, borderRadius: radius.lg, overflow: 'hidden', backgroundColor: '#000', marginBottom: space.md },
  permission: { flex: 1, alignItems: 'stretch', justifyContent: 'center', padding: space.xl, backgroundColor: colors.surface },
  permissionText: { color: colors.ink, textAlign: 'center', marginBottom: space.md, lineHeight: 20 },
});
